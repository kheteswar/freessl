# 🔒 FreeSSL - Free SSL Certificate Generator

Generate free SSL/TLS certificates using Let's Encrypt with an easy-to-use web interface. Support for wildcard certificates, multiple domains, and DNS-01 validation.

![Version](https://img.shields.io/badge/version-1.0-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![PHP](https://img.shields.io/badge/PHP-7.4%2B-purple)

## ✨ Features

- 🎯 **Easy 4-Step Process** - Register, order, verify, download
- 🌐 **Wildcard Certificates** - Secure *.yourdomain.com
- 📋 **Multiple Domains** - One certificate, multiple domains
- 🔒 **Client-Side Security** - Private keys never leave your browser
- 🧪 **Staging Mode** - Test with Let's Encrypt staging environment
- 📊 **Analytics Dashboard** - Track usage statistics
- 🎨 **Modern UI** - Beautiful, responsive design with Tailwind CSS
- ⚡ **Fast & Lightweight** - No database required
- 💰 **Cost Savings** - Track money saved vs paid SSL certificates
- 🔐 **Zero-Knowledge Architecture** - Server never sees your private keys

## 🚀 Live Demo

**Try it now:** [https://coderyogi.com/tool/freessl/](https://coderyogi.com/tool/freessl/)

## 🔧 Requirements

- PHP 7.4 or higher
- Web server (Apache/Nginx)
- OpenSSL extension enabled
- Write permissions for analytics directory

## 📦 Installation

### Quick Start

1. **Clone the repository:**
```bash
git clone https://github.com/kheteswar/freessl.git
cd freessl
```

2. **Upload to your web server:**
```bash
cp index.php /var/www/html/freessl/
cp analytics.php /var/www/html/freessl/
```

3. **Set permissions:**
```bash
chmod 755 /var/www/html/freessl/
mkdir /var/www/html/freessl/analytics
chmod 755 /var/www/html/freessl/analytics
```

4. **Configure analytics password:**

Edit `analytics.php` line 10:
```php
$ANALYTICS_PASSWORD = 'your_secure_password_here';
```

5. **Access in browser:**
```
https://yourdomain.com/freessl/
```

## 📖 Usage

### Generate a Certificate

1. **Register** - Enter your email address
2. **Create Order** - Enter your domain(s)
3. **DNS Verification** - Add DNS TXT records
4. **Finalize** - Download your certificate

### Wildcard Certificates

```
yourdomain.com
*.yourdomain.com
```

### Multiple Domains

```
example.com
www.example.com
api.example.com
```

## 🔒 Security Features

- **Client-Side Key Generation** - Web Crypto API
- **CSR Generated in Browser** - Forge.js
- **Zero-Knowledge Architecture** - No private keys transmitted
- **Verifiable** - Check F12 Network tab

## 📊 Analytics Dashboard

Access: `https://yourdomain.com/freessl/analytics.php`

Features:
- Page visits tracking
- Certificate orders
- Production vs Staging breakdown
- Recent activity

## 🤝 Contributing

Contributions welcome! Please:
1. Fork the repository
2. Create feature branch
3. Commit changes
4. Push to branch
5. Open Pull Request

## 📝 License

MIT License - see [LICENSE](LICENSE) file

## 📧 Contact

**Kheteshwar Boravat**
- GitHub: [@kheteswar](https://github.com/kheteswar)
- LinkedIn: [in/kheteswar](https://www.linkedin.com/in/kheteswar/)
- Website: [coderyogi.com](https://coderyogi.com)

**Project Links:**
- Repository: [https://github.com/kheteswar/freessl](https://github.com/kheteswar/freessl)
- Live Demo: [https://coderyogi.com/tool/freessl/](https://coderyogi.com/tool/freessl/)
- Issues: [Report a bug](https://github.com/kheteswar/freessl/issues)

## 🌟 Show Support

If this helped you, please ⭐ star this repository!

---

Made with ❤️ using PHP, JavaScript, and Let's Encrypt# freessl
