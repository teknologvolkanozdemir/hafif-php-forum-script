# Hafif Forum

Türkçe arayüzlü, PHP ve PDO ile çalışan, üyelik ve konu/yanıt özelliklerine sahip basit bir forum. Harici kütüphane veya derleme adımı gerekmez.

## Özellikler

- Üyelik oluşturma, oturum açma ve güvenli oturum kapatma
- Şifrelerin `password_hash` ile saklanması
- Bölümler, konu açma, yanıt yazma ve konu/yanıt silme
- Konu başlığı ve mesaj içeriğinde arama
- İlk kayıt olan üyeye yönetici rolü; kendi içeriğini silme ve yönetici olarak tüm konuları/yanıtları silme
- CSRF korumalı formlar ve PDO parametreli sorgular
- Responsive Türkçe arayüz

## Gereksinimler

- PHP 8.1 veya üzeri
- PDO, mbstring ve PDO_SQLite (varsayılan) veya PDO_MySQL
- SQLite kullanırken uygulama dizininde SQLite dosyası oluşturma/yazma izni

## Kurulum

1. Depoyu web sunucunuzun PHP tarafından çalıştırılabilen dizinine alın.
2. Varsayılan SQLite veritabanını kullanıyorsanız ek kurulum gerekmez. İlk istek tabloları ve varsayılan bölümleri oluşturur.
3. Geliştirme sunucusunu başlatın:

   ```sh
   php -S 127.0.0.1:8000
   ```

4. `http://127.0.0.1:8000` adresini açın. İlk oluşturulan hesap yönetici olur; sonraki kayıtlar normal üye olarak açılır. Bu nedenle herkese açık kurulumu açmadan önce yönetici hesabını oluşturun.

### MySQL kullanımı

Veritabanını ve kullanıcıyı hosting panelinizden oluşturun, ardından PHP uygulamasını çalıştıran ortamda aşağıdaki değişkenleri ayarlayın:

```sh
export FORUM_DSN='mysql:host=127.0.0.1;dbname=hafif_forum;charset=utf8mb4'
export FORUM_DB_USER='forum_user'
export FORUM_DB_PASSWORD='your-database-password'
```

Uygulama tabloları ilk istek sırasında oluşturur. Veritabanı kullanıcısının tablo ve indeks oluşturma, okuma ve yazma izinleri olmalıdır. Üretimde veritabanı parolasını kaynak koda değil ortam değişkenlerine veya sunucunun gizli yapılandırmasına koyun.

## Yapılandırma

| Değişken | Varsayılan | Açıklama |
| --- | --- | --- |
| `FORUM_DSN` | `sqlite:<uygulama dizini>/forum.sqlite` | PDO bağlantı dizesi |
| `FORUM_DB_USER` | boş | Veritabanı kullanıcı adı |
| `FORUM_DB_PASSWORD` | boş | Veritabanı parolası |

SQLite dosyasını içeren dizinin PHP tarafından yazılabilir olduğundan ve veritabanı dosyasının web sunucusu tarafından doğrudan indirilemediğinden emin olun. Üretimde HTTPS kullanın.
