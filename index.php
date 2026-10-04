<?php
declare(strict_types=1);

session_start([
    'cookie_httponly' => true,
    'cookie_samesite' => 'Lax',
    'cookie_secure' => !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off',
    'use_strict_mode' => true,
]);

$dsn = getenv('FORUM_DSN') ?: 'sqlite:' . __DIR__ . '/forum.sqlite';
$dbUser = getenv('FORUM_DB_USER') ?: null;
$dbPassword = getenv('FORUM_DB_PASSWORD') ?: null;

try {
    $db = new PDO($dsn, $dbUser, $dbPassword, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES => false,
    ]);
} catch (PDOException $exception) {
    http_response_code(500);
    exit('Veritabanına bağlanılamadı. FORUM_DSN ayarınızı kontrol edin.');
}

$driver = $db->getAttribute(PDO::ATTR_DRIVER_NAME);
$idColumn = $driver === 'sqlite'
    ? 'INTEGER PRIMARY KEY AUTOINCREMENT'
    : 'BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY';
$db->exec("CREATE TABLE IF NOT EXISTS users (
    id $idColumn,
    username VARCHAR(30) NOT NULL UNIQUE,
    email VARCHAR(190) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    role VARCHAR(20) NOT NULL DEFAULT 'member',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
)");
$db->exec("CREATE TABLE IF NOT EXISTS categories (
    id $idColumn,
    name VARCHAR(80) NOT NULL UNIQUE,
    description VARCHAR(255) NOT NULL DEFAULT ''
)");
$db->exec("CREATE TABLE IF NOT EXISTS topics (
    id $idColumn,
    category_id BIGINT NOT NULL,
    user_id BIGINT NOT NULL,
    title VARCHAR(150) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
)");
$db->exec("CREATE TABLE IF NOT EXISTS posts (
    id $idColumn,
    topic_id BIGINT NOT NULL,
    user_id BIGINT NOT NULL,
    body TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
)");
foreach (['topics_category_idx' => 'topics (category_id)', 'posts_topic_idx' => 'posts (topic_id)'] as $index => $table) {
    if ($driver === 'sqlite') {
        $db->exec("CREATE INDEX IF NOT EXISTS $index ON $table");
    } elseif ($driver === 'mysql') {
        $existingIndex = $db->query("SHOW INDEX FROM " . explode(' ', $table)[0] . " WHERE Key_name = '$index'")->fetch();
        if (!$existingIndex) {
            $db->exec("CREATE INDEX $index ON $table");
        }
    }
}
$count = (int) $db->query('SELECT COUNT(*) FROM categories')->fetchColumn();
if ($count === 0) {
    $insertCategory = $db->prepare('INSERT INTO categories (name, description) VALUES (?, ?)');
    foreach ([
        ['Genel', 'Genel konularınızı burada paylaşın.'],
        ['Yardım', 'Sorularınızı sorun, birlikte çözelim.'],
        ['Duyurular', 'Forumdan haberler ve duyurular.'],
    ] as [$name, $description]) {
        $insertCategory->execute([$name, $description]);
    }
}

function escape(string $value): string
{
    return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function currentUser(): ?array
{
    return $_SESSION['user'] ?? null;
}

function isAdmin(): bool
{
    return (currentUser()['role'] ?? '') === 'admin';
}

function csrfToken(): string
{
    if (!isset($_SESSION['csrf'])) {
        $_SESSION['csrf'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf'];
}

function csrfField(): string
{
    return '<input type="hidden" name="csrf" value="' . escape(csrfToken()) . '">';
}

function requirePost(): void
{
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        http_response_code(405);
        exit('Bu işlem için POST isteği gereklidir.');
    }
    if (!isset($_POST['csrf']) || !hash_equals(csrfToken(), (string) $_POST['csrf'])) {
        http_response_code(400);
        exit('Form doğrulaması başarısız. Sayfayı yenileyip tekrar deneyin.');
    }
}

function requireLogin(): array
{
    $user = currentUser();
    if ($user === null) {
        throw new RuntimeException('Bu işlem için önce giriş yapmalısınız.');
    }
    return $user;
}

function redirect(string $url = 'index.php'): never
{
    header('Location: ' . $url);
    exit;
}

$notice = $_SESSION['notice'] ?? '';
unset($_SESSION['notice']);
$error = '';
$action = (string) ($_POST['action'] ?? '');

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    try {
        requirePost();
        switch ($action) {
            case 'register':
                $username = trim((string) ($_POST['username'] ?? ''));
                $email = trim((string) ($_POST['email'] ?? ''));
                $password = (string) ($_POST['password'] ?? '');
                if (!preg_match('/^[\p{L}\p{N}_-]{3,30}$/u', $username)) {
                    throw new RuntimeException('Kullanıcı adı 3–30 karakter olmalı; harf, rakam, _ ve - kullanılabilir.');
                }
                if (!filter_var($email, FILTER_VALIDATE_EMAIL) || strlen($email) > 190) {
                    throw new RuntimeException('Geçerli bir e-posta adresi girin.');
                }
                if (strlen($password) < 8) {
                    throw new RuntimeException('Parolanız en az 8 karakter olmalı.');
                }
                $db->beginTransaction();
                $userCount = (int) $db->query('SELECT COUNT(*) FROM users')->fetchColumn();
                $insert = $db->prepare('INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)');
                $insert->execute([$username, $email, password_hash($password, PASSWORD_DEFAULT), $userCount === 0 ? 'admin' : 'member']);
                $id = (int) $db->lastInsertId();
                $db->commit();
                session_regenerate_id(true);
                $_SESSION['user'] = ['id' => $id, 'username' => $username, 'role' => $userCount === 0 ? 'admin' : 'member'];
                $_SESSION['csrf'] = bin2hex(random_bytes(32));
                $_SESSION['notice'] = 'Hesabınız oluşturuldu. Hoş geldiniz!';
                redirect();

            case 'login':
                $login = trim((string) ($_POST['login'] ?? ''));
                $query = $db->prepare('SELECT id, username, email, password, role FROM users WHERE username = ? OR email = ?');
                $query->execute([$login, $login]);
                $user = $query->fetch();
                if (!$user || !password_verify((string) ($_POST['password'] ?? ''), $user['password'])) {
                    throw new RuntimeException('Kullanıcı adı/e-posta veya parola hatalı.');
                }
                session_regenerate_id(true);
                $_SESSION['user'] = ['id' => (int) $user['id'], 'username' => $user['username'], 'role' => $user['role']];
                $_SESSION['csrf'] = bin2hex(random_bytes(32));
                $_SESSION['notice'] = 'Tekrar hoş geldiniz, ' . $user['username'] . '!';
                redirect();

            case 'logout':
                unset($_SESSION['user']);
                session_regenerate_id(true);
                $_SESSION['csrf'] = bin2hex(random_bytes(32));
                $_SESSION['notice'] = 'Oturumunuz kapatıldı.';
                redirect();

            case 'topic':
                $user = requireLogin();
                $title = trim((string) ($_POST['title'] ?? ''));
                $body = trim((string) ($_POST['body'] ?? ''));
                $categoryId = filter_var($_POST['category_id'] ?? null, FILTER_VALIDATE_INT);
                if ($title === '' || mb_strlen($title) > 150) {
                    throw new RuntimeException('Başlık 1–150 karakter arasında olmalı.');
                }
                if ($body === '' || mb_strlen($body) > 20000) {
                    throw new RuntimeException('Mesaj 1–20.000 karakter arasında olmalı.');
                }
                $category = $db->prepare('SELECT id FROM categories WHERE id = ?');
                $category->execute([$categoryId]);
                if (!$category->fetch()) {
                    throw new RuntimeException('Lütfen geçerli bir bölüm seçin.');
                }
                $db->beginTransaction();
                $insertTopic = $db->prepare('INSERT INTO topics (category_id, user_id, title) VALUES (?, ?, ?)');
                $insertTopic->execute([$categoryId, $user['id'], $title]);
                $topicId = (int) $db->lastInsertId();
                $insertPost = $db->prepare('INSERT INTO posts (topic_id, user_id, body) VALUES (?, ?, ?)');
                $insertPost->execute([$topicId, $user['id'], $body]);
                $db->commit();
                $_SESSION['notice'] = 'Konunuz yayınlandı.';
                redirect('index.php?topic=' . $topicId);

            case 'reply':
                $user = requireLogin();
                $topicId = filter_var($_POST['topic_id'] ?? null, FILTER_VALIDATE_INT);
                $body = trim((string) ($_POST['body'] ?? ''));
                if (!$topicId || $body === '' || mb_strlen($body) > 20000) {
                    throw new RuntimeException('Yanıtınızı kontrol edin (en fazla 20.000 karakter).');
                }
                $topic = $db->prepare('SELECT id FROM topics WHERE id = ?');
                $topic->execute([$topicId]);
                if (!$topic->fetch()) {
                    throw new RuntimeException('Konu bulunamadı.');
                }
                $insert = $db->prepare('INSERT INTO posts (topic_id, user_id, body) VALUES (?, ?, ?)');
                $insert->execute([$topicId, $user['id'], $body]);
                $_SESSION['notice'] = 'Yanıtınız yayınlandı.';
                redirect('index.php?topic=' . $topicId);

            case 'delete_topic':
                $user = requireLogin();
                $topicId = filter_var($_POST['topic_id'] ?? null, FILTER_VALIDATE_INT);
                $topic = $db->prepare('SELECT user_id FROM topics WHERE id = ?');
                $topic->execute([$topicId]);
                $owner = $topic->fetchColumn();
                if ($owner === false || ((int) $owner !== $user['id'] && !isAdmin())) {
                    throw new RuntimeException('Bu konuyu silme yetkiniz yok.');
                }
                $db->beginTransaction();
                $db->prepare('DELETE FROM posts WHERE topic_id = ?')->execute([$topicId]);
                $db->prepare('DELETE FROM topics WHERE id = ?')->execute([$topicId]);
                $db->commit();
                $_SESSION['notice'] = 'Konu silindi.';
                redirect();

            case 'delete_post':
                $user = requireLogin();
                $postId = filter_var($_POST['post_id'] ?? null, FILTER_VALIDATE_INT);
                $post = $db->prepare('SELECT user_id, topic_id FROM posts WHERE id = ?');
                $post->execute([$postId]);
                $row = $post->fetch();
                if (!$row || ((int) $row['user_id'] !== $user['id'] && !isAdmin())) {
                    throw new RuntimeException('Bu yanıtı silme yetkiniz yok.');
                }
                $topicId = (int) $row['topic_id'];
                if ((int) $db->query('SELECT COUNT(*) FROM posts WHERE topic_id = ' . $topicId)->fetchColumn() <= 1) {
                    throw new RuntimeException('Konunun ilk mesajı silinemez. Konunun tamamını silebilirsiniz.');
                }
                $db->prepare('DELETE FROM posts WHERE id = ?')->execute([$postId]);
                $_SESSION['notice'] = 'Yanıt silindi.';
                redirect('index.php?topic=' . $topicId);

            default:
                throw new RuntimeException('Geçersiz işlem.');
        }
    } catch (RuntimeException $exception) {
        if ($db->inTransaction()) {
            $db->rollBack();
        }
        $error = $exception->getMessage();
    } catch (PDOException $exception) {
        if ($db->inTransaction()) {
            $db->rollBack();
        }
        $error = $exception->getCode() === '23000'
            ? 'Bu kullanıcı adı veya e-posta adresi zaten kullanılıyor.'
            : 'İşlem tamamlanamadı. Lütfen tekrar deneyin.';
    }
}

$user = currentUser();
$categories = $db->query('SELECT c.id, c.name, c.description, COUNT(t.id) AS topic_count
    FROM categories c LEFT JOIN topics t ON t.category_id = c.id
    GROUP BY c.id, c.name, c.description ORDER BY c.id')->fetchAll();
$topicId = filter_var($_GET['topic'] ?? null, FILTER_VALIDATE_INT);
$categoryId = filter_var($_GET['category'] ?? null, FILTER_VALIDATE_INT);
$search = trim((string) ($_GET['q'] ?? ''));
$topic = null;
$posts = [];
if ($topicId) {
    $query = $db->prepare('SELECT t.id, t.title, t.user_id, t.created_at, c.name AS category_name,
        u.username FROM topics t JOIN categories c ON c.id = t.category_id JOIN users u ON u.id = t.user_id
        WHERE t.id = ?');
    $query->execute([$topicId]);
    $topic = $query->fetch() ?: null;
    if ($topic) {
        $query = $db->prepare('SELECT p.id, p.user_id, p.body, p.created_at, u.username, u.role
            FROM posts p JOIN users u ON u.id = p.user_id WHERE p.topic_id = ? ORDER BY p.id');
        $query->execute([$topicId]);
        $posts = $query->fetchAll();
    }
} else {
    $sql = 'SELECT t.id, t.title, t.created_at, c.name AS category_name, c.id AS category_id,
        u.username, COUNT(p.id) AS reply_count, MAX(p.created_at) AS last_post
        FROM topics t JOIN categories c ON c.id = t.category_id JOIN users u ON u.id = t.user_id
        LEFT JOIN posts p ON p.topic_id = t.id';
    $conditions = [];
    $params = [];
    if ($categoryId) {
        $conditions[] = 'c.id = ?';
        $params[] = $categoryId;
    }
    if ($search !== '') {
        $conditions[] = '(t.title LIKE ? OR p.body LIKE ?)';
        $params[] = '%' . $search . '%';
        $params[] = '%' . $search . '%';
    }
    if ($conditions) {
        $sql .= ' WHERE ' . implode(' AND ', $conditions);
    }
    $sql .= ' GROUP BY t.id, t.title, t.created_at, c.name, c.id, u.username ORDER BY last_post DESC, t.id DESC';
    $query = $db->prepare($sql);
    $query->execute($params);
    $topics = $query->fetchAll();
}

?><!doctype html>
<html lang="tr">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title><?= $topic ? escape($topic['title']) . ' · ' : '' ?>Hafif Forum</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
<header class="site-header">
    <div class="header-inner">
        <a class="brand" href="index.php"><span class="brand-mark">H</span><span>Hafif Forum<small>Birlikte konuşalım</small></span></a>
        <nav>
            <a href="index.php">Forum</a>
            <?php if ($user): ?>
                <span class="welcome">Merhaba, <?= escape($user['username']) ?><?= isAdmin() ? ' · Yönetici' : '' ?></span>
                <form class="inline-form" method="post"><?= csrfField() ?><input type="hidden" name="action" value="logout"><button class="nav-button" type="submit">Çıkış</button></form>
            <?php else: ?>
                <a href="#giris">Giriş</a><a class="nav-join" href="#kayit">Üye ol</a>
            <?php endif; ?>
        </nav>
    </div>
</header>
<main class="layout">
    <section class="main-column">
        <div class="hero">
            <div><span class="eyebrow">TOPLULUĞUMUZA HOŞ GELDİNİZ</span><h1>Fikirler burada<br><em>hayat bulur.</em></h1>
                <p>Sor, paylaş, öğren. Güzel sohbetler için doğru yerdesin.</p></div>
            <div class="hero-art" aria-hidden="true"><span>✦</span><b>💬</b><i>✳</i></div>
        </div>

        <?php if ($notice): ?><div class="alert success"><?= escape((string) $notice) ?></div><?php endif; ?>
        <?php if ($error): ?><div class="alert error"><?= escape($error) ?></div><?php endif; ?>

        <?php if ($topic): ?>
            <div class="section-heading topic-heading">
                <div><a class="back-link" href="index.php">← Tüm konular</a><span class="eyebrow"><?= escape($topic['category_name']) ?></span>
                    <h2><?= escape($topic['title']) ?></h2><p><?= escape($topic['username']) ?> · <?= escape($topic['created_at']) ?></p></div>
                <?php if ($user && ((int) $user['id'] === (int) $topic['user_id'] || isAdmin())): ?>
                    <form method="post" onsubmit="return confirm('Bu konuyu ve tüm yanıtlarını silmek istediğinize emin misiniz?')"><?= csrfField() ?><input type="hidden" name="action" value="delete_topic"><input type="hidden" name="topic_id" value="<?= (int) $topic['id'] ?>"><button class="button button-danger" type="submit">Konuyu sil</button></form>
                <?php endif; ?>
            </div>
            <div class="post-list">
                <?php foreach ($posts as $index => $post): ?>
                    <article class="post-card">
                        <div class="post-user"><div class="avatar"><?= escape(mb_strtoupper(mb_substr($post['username'], 0, 1))) ?></div><strong><?= escape($post['username']) ?></strong><?php if ($post['role'] === 'admin'): ?><span class="admin-tag">Yönetici</span><?php endif; ?><small><?= escape($post['created_at']) ?></small></div>
                        <div class="post-content"><span class="post-number">#<?= $index + 1 ?></span><p><?= nl2br(escape($post['body'])) ?></p>
                            <?php if ($user && ((int) $user['id'] === (int) $post['user_id'] || isAdmin()) && $index > 0): ?>
                                <form method="post" onsubmit="return confirm('Bu yanıt silinsin mi?')"><?= csrfField() ?><input type="hidden" name="action" value="delete_post"><input type="hidden" name="post_id" value="<?= (int) $post['id'] ?>"><button class="text-button" type="submit">Yanıtı sil</button></form>
                            <?php endif; ?>
                        </div>
                    </article>
                <?php endforeach; ?>
            </div>
            <?php if ($user): ?>
                <form class="composer" method="post"><?= csrfField() ?><input type="hidden" name="action" value="reply"><input type="hidden" name="topic_id" value="<?= (int) $topic['id'] ?>">
                    <label for="reply-body">Yanıtını yaz</label><textarea id="reply-body" name="body" maxlength="20000" required rows="5" placeholder="Düşünceni toplulukla paylaş..."></textarea><button class="button button-primary" type="submit">Yanıtı yayınla <span>→</span></button>
                </form>
            <?php else: ?><div class="empty-state">Yanıt yazmak için <a href="#giris">giriş yapın</a> veya <a href="#kayit">üye olun</a>.</div><?php endif; ?>
        <?php else: ?>
            <div class="section-heading">
                <div><span class="eyebrow"><?= $search !== '' ? 'ARAMA SONUÇLARI' : 'TOPLULUK' ?></span><h2><?= $search !== '' ? '“' . escape($search) . '” için sonuçlar' : 'Son konuşmalar' ?></h2></div>
                <?php if ($user): ?><a class="button button-primary" href="#yeni-konu">＋ Yeni konu</a><?php else: ?><a class="button button-primary" href="#giris">＋ Konu aç</a><?php endif; ?>
            </div>
            <?php if ($topics): ?>
                <div class="topic-list">
                    <?php foreach ($topics as $row): ?>
                        <a class="topic-row" href="index.php?topic=<?= (int) $row['id'] ?>">
                            <span class="topic-icon">✳</span><span class="topic-info"><strong><?= escape($row['title']) ?></strong><small><?= escape($row['category_name']) ?> <span>·</span> <?= escape($row['username']) ?> <span>·</span> <?= escape($row['last_post']) ?></small></span>
                            <span class="reply-count"><?= max(0, (int) $row['reply_count'] - 1) ?><small>yanıt</small></span><span class="row-arrow">→</span>
                        </a>
                    <?php endforeach; ?>
                </div>
            <?php else: ?>
                <div class="empty-state"><span>✧</span><strong>Henüz konuşma yok.</strong><p>İlk konuyu açıp sohbeti başlatabilirsiniz.</p></div>
            <?php endif; ?>
        <?php endif; ?>
    </section>

    <aside class="sidebar">
        <form class="search-box" method="get"><label for="search">Forumda ara</label><div><input id="search" name="q" value="<?= escape($search) ?>" placeholder="Bir konu ara..."><button aria-label="Ara" type="submit">⌕</button></div></form>
        <section class="side-card"><div class="side-title"><h3>Forum bölümleri</h3><span>✳</span></div>
            <?php foreach ($categories as $category): ?><a class="category-link" href="index.php?category=<?= (int) $category['id'] ?>"><span class="category-dot"></span><span><?= escape($category['name']) ?><small><?= escape($category['description']) ?></small></span><b><?= (int) $category['topic_count'] ?></b></a><?php endforeach; ?>
        </section>
        <?php if ($user): ?>
            <section class="side-card new-topic-card" id="yeni-konu"><span class="eyebrow">PAYLAŞIM ZAMANI</span><h3>Yeni bir konuşma başlat</h3><p>Aklındaki soruyu sor veya topluluğa bir şey anlat.</p>
                <form method="post"><?= csrfField() ?><input type="hidden" name="action" value="topic">
                    <label for="topic-title">Konu başlığı</label><input id="topic-title" name="title" maxlength="150" required placeholder="Konunuzun başlığı">
                    <label for="topic-category">Bölüm</label><select id="topic-category" name="category_id" required><?php foreach ($categories as $category): ?><option value="<?= (int) $category['id'] ?>"><?= escape($category['name']) ?></option><?php endforeach; ?></select>
                    <label for="topic-body">Mesajınız</label><textarea id="topic-body" name="body" maxlength="20000" rows="4" required placeholder="Konuyu biraz daha anlatın..."></textarea>
                    <button class="button button-primary button-full" type="submit">Konuyu yayınla <span>→</span></button>
                </form>
            </section>
        <?php else: ?>
            <section class="side-card auth-card" id="giris"><span class="eyebrow">TOPLULUĞA KATIL</span><h3>Güzel sohbetler<br>bir üyelik uzağında.</h3>
                <form method="post"><?= csrfField() ?><input type="hidden" name="action" value="login"><label for="login">Kullanıcı adı veya e-posta</label><input id="login" name="login" required autocomplete="username" placeholder="kullaniciadi">
                    <label for="password">Parola</label><input id="password" name="password" type="password" required autocomplete="current-password" placeholder="••••••••"><button class="button button-primary button-full" type="submit">Giriş yap <span>→</span></button></form>
                <p class="auth-switch">Henüz üye değil misin? <a href="#kayit">Hemen katıl</a></p>
            </section>
            <section class="side-card register-card" id="kayit"><h3>Yeni üyelik</h3><form method="post"><?= csrfField() ?><input type="hidden" name="action" value="register">
                <label for="username">Kullanıcı adı</label><input id="username" name="username" minlength="3" maxlength="30" required autocomplete="username" placeholder="kullaniciadi">
                <label for="email">E-posta</label><input id="email" name="email" type="email" maxlength="190" required autocomplete="email" placeholder="siz@ornek.com">
                <label for="new-password">Parola <small>(en az 8 karakter)</small></label><input id="new-password" name="password" type="password" minlength="8" required autocomplete="new-password" placeholder="••••••••">
                <button class="button button-dark button-full" type="submit">Ücretsiz üye ol <span>→</span></button></form>
            </section>
        <?php endif; ?>
        <p class="side-foot">Hafif Forum <span>·</span> İyi sohbetler ✦</p>
    </aside>
</main>
<footer><span>Hafif Forum</span><span>Birbirimize iyi davranalım. ✳</span></footer>
</body>
</html>
