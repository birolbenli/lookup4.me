"""Lightweight EN/TR translations for the site UI."""

from __future__ import annotations

from flask import g, request

SUPPORTED = ("en", "tr")
DEFAULT = "en"
COOKIE = "lang"

# English source strings → Turkish
TR: dict[str, str] = {
    # Nav / chrome
    "Tools": "Araçlar",
    "Report": "Bildir",
    "About": "Hakkında",
    "Privacy": "Gizlilik",
    "My IP": "IP’m",
    "Open menu": "Menüyü aç",
    "Close menu": "Menüyü kapat",
    "Language": "Dil",
    "Buy me a coffee": "Bir kahve ısmarla",
    "Your IP": "IP adresiniz",
    "IP Lookup": "IP Sorgula",
    "queries": "sorgular",
    "Total successful tool queries": "Başarılı toplam sorgu sayısı",
    "Open visitor map": "Ziyaretçi haritasını aç",
    "Visitors around the world": "Dünyadan ziyaretçiler",
    "Unique visitors by country (approx.)": "Ülkelere göre yaklaşık benzersiz ziyaretçiler",
    "Thank you for using our tools. If you find them useful, you can buy me a coffee — it keeps the lights on.": "Araçlarımızı kullandığınız için teşekkür ederiz. Faydalı bulduysanız bana bir kahve ısmarlayabilirsiniz — bu sayede hizmeti ayakta tutuyoruz.",
    "Buy me a coffee →": "Bir kahve ısmarla →",
    "Contact": "İletişim",
    "Close": "Kapat",
    "Loading map…": "Harita yükleniyor…",
    "No visitor data yet.": "Henüz ziyaretçi verisi yok.",
    "visitors": "ziyaretçi",
    "countries": "ülke",
    "Top countries": "Öne çıkan ülkeler",
    "Free DNS, email authentication, IP and SSL lookup tools.": "Ücretsiz DNS, e-posta kimlik doğrulama, IP ve SSL sorgu araçları.",
    # Home
    "DNS, email & network tools": "DNS, e-posta ve ağ araçları",
    "Pick a tool and run a lookup. Shareable URLs start instantly — for example:": "Bir araç seçip sorgulayın. Paylaşılabilir adresler anında çalışır — örneğin:",
    "Email Header Analyzer": "E-posta Başlık Analizi",
    # Common UI
    "Lookup": "Sorgula",
    "Switch tool": "Araç değiştir",
    "DNS type": "DNS türü",
    "Direct URL:": "Doğrudan adres:",
    "Try {example}": "{example} dene",
    "Page not found": "Sayfa bulunamadı",
    "That page does not exist.": "Bu sayfa mevcut değil.",
    "Back to tools": "Araçlara dön",
    # About
    "About": "Hakkında",
    "{site} is a small collection of practical DNS, email authentication, IP and SSL tools. Open a tool, enter a value, or paste a direct URL and get a clear result.": "{site} pratik DNS, e-posta kimlik doğrulama, IP ve SSL araçlarından oluşan küçük bir koleksiyondur. Bir araç açın, değer girin veya doğrudan bir adres yapıştırın; net sonuç alın.",
    "Built by": "Geliştiren",
    "Direct URLs": "Doğrudan adresler",
    "Every tool accepts {pattern} and runs immediately.": "Her araç {pattern} biçimini kabul eder ve hemen çalışır.",
    "IP / curl": "IP / curl",
    "Mail Tester DNS": "Mail Tester DNS",
    "For Mail Tester delivery, point MX for {domain} to this server IP and keep port 25 open.": "Mail Tester teslimatı için {domain} alanının MX kaydını bu sunucu IP’sine yönlendirin ve 25 numaralı portu açık tutun.",
    "Usage": "Kullanım",
    "Quiet counter of lookups performed on this instance.": "Bu kurulumda yapılan sorguların sakin sayacı.",
    "Tool": "Araç",
    "Queries": "Sorgular",
    # Feedback
    "Issue & feature request": "Sorun ve özellik isteği",
    "Found a bug or have an idea? Send it here — reports go to {email}.": "Hata buldunuz veya bir fikriniz mi var? Buradan gönderin — bildirimler {email} adresine gider.",
    "Privacy:": "Gizlilik:",
    "Do not include passwords, tokens, or confidential message content.": "Parola, token veya gizli ileti içeriği eklemeyin.",
    "Redaction guide →": "Sansür rehberi →",
    "Type": "Tür",
    "Bug report": "Hata bildirimi",
    "Issue": "Sorun",
    "Feature request": "Özellik isteği",
    "Your email (optional)": "E-posta (isteğe bağlı)",
    "Title": "Başlık",
    "Short summary": "Kısa özet",
    "Details": "Ayrıntılar",
    "What happened, what you expected, or the feature you want…": "Ne oldu, ne bekliyordunuz veya istediğiniz özellik…",
    "Related page URL (optional)": "İlgili sayfa adresi (isteğe bağlı)",
    "Send report": "Bildirimi gönder",
    "Report an issue / Feature request": "Sorun bildir / Özellik iste",
    # Privacy
    "Privacy & redaction guide": "Gizlilik ve sansür rehberi",
    "{site} tools are meant for technical debugging. Do not paste secrets, customer data, or anything you would not want stored or logged by mistake. You are responsible for every value you submit.": "{site} araçları teknik hata ayıklama içindir. Gizli bilgi, müşteri verisi veya yanlışlıkla saklanmasını/istemediğiniz hiçbir şeyi yapıştırmayın. Gönderdiğiniz her değerden siz sorumlusunuz.",
    "Important:": "Önemli:",
    "Email headers and full message sources can contain personal names, addresses, internal hostnames, tracking IDs, authentication tokens, and business content. Redact before pasting whenever possible.": "E-posta başlıkları ve tam ileti kaynakları kişisel adlar, adresler, iç sunucu adları, izleme kimlikleri, kimlik doğrulama token’ları ve iş içeriği içerebilir. Mümkün olduğunda yapıştırmadan önce sansürleyin.",
    "What to remove or mask": "Kaldırılacak veya maskelenecekler",
    "Quick redaction method": "Hızlı sansür yöntemi",
    "Example": "Örnek",
    "What we store": "Ne saklıyoruz",
    "Report titles and messages you submit via the feedback form (and optional contact email).": "Geri bildirim formuyla gönderdiğiniz başlık ve mesajlar (ve isteğe bağlı iletişim e-postası).",
    "Aggregate query counters (tool name → count), not the query contents.": "Toplu sorgu sayaçları (araç adı → sayı); sorgu içeriği değil.",
    "Mail Tester messages only for the lifetime of that temporary inbox.": "Mail Tester iletileri yalnızca o geçici gelen kutusu yaşam süresince.",
    "Prefer headers-only analysis when you can.": "Mümkünse yalnızca başlık analizi tercih edin.",
    # Headers / mailtest page chrome
    "Paste the full source (“Show original”) for the richest report.": "En zengin rapor için tam kaynağı (“Özgününü göster”) yapıştırın.",
    "Security & privacy:": "Güvenlik ve gizlilik:",
    "Do not paste passwords, tokens, customer data, or confidential message content. You are responsible for anything you submit.": "Parola, token, müşteri verisi veya gizli ileti içeriği yapıştırmayın. Gönderdiğiniz her şeyden siz sorumlusunuz.",
    "How to redact sensitive details before pasting →": "Yapıştırmadan önce hassas ayrıntıları nasıl sansürlersiniz →",
    "Analyze headers": "Başlıkları analiz et",
    "Paste": "Yapıştır",
    "Clear": "Temizle",
    "Raw email source / headers": "Ham e-posta kaynağı / başlıklar",
    "Tip:": "İpucu:",
    "Prefer headers-only. Redact names, subjects, and personal addresses first —": "Mümkünse yalnızca başlık kullanın. Önce adları, konuları ve kişisel adresleri sansürleyin —",
    "redaction guide": "sansür rehberi",
    "Best on HTTPS:": "En iyisi HTTPS’te:",
    "Like mail-tester.com — send one message to your unique address and get a score with fixes.": "mail-tester.com benzeri — benzersiz adresinize bir ileti gönderin; puan ve düzeltmeler alın.",
    "Do not send confidential or production emails here. Temporary inboxes can receive full message content. You are responsible for what you send.": "Buraya gizli veya üretim e-postaları göndermeyin. Geçici gelen kutuları tam ileti içeriğini alabilir. Gönderdiğinizden siz sorumlusunuz.",
    "Privacy & redaction guide →": "Gizlilik ve sansür rehberi →",
    "Create test address": "Test adresi oluştur",
    "Send an email to this address, then keep this page open:": "Bu adrese bir e-posta gönderin ve bu sayfayı açık tutun:",
    "Copy": "Kopyala",
    "Waiting for your message…": "İletiniz bekleniyor…",
    "Inbox domain:": "Gelen kutusu alanı:",
    "MX for this domain must point to this server’s IP for delivery to work.": "Teslimatın çalışması için bu alanın MX kaydı bu sunucunun IP’sine bakmalıdır.",
    # Privacy list items (kept concise)
    "Email addresses of people (keep only domains if needed)": "Kişilerin e-posta adresleri (gerekirse yalnızca alan adını bırakın)",
    "Names in From / To / Cc display names": "From / To / Cc görünen adlarındaki isimler",
    "Subjects that reveal private topics — replace with [REDACTED]": "Özel konuları açığa çıkaran konular — [REDACTED] ile değiştirin",
    "Message bodies — prefer headers-only unless body analysis is required": "İleti gövdeleri — gövde analizi gerekmiyorsa yalnızca başlık kullanın",
    "Cookies / tokens / API keys in custom headers": "Özel başlıklardaki çerez / token / API anahtarları",
    "Internal IPs / hostnames if they are sensitive in your environment": "Ortamınızda hassassa iç IP / sunucu adları",
    "DKIM / ARC signatures are usually fine to keep for auth checks; body content is not": "DKIM / ARC imzaları kimlik doğrulama için genelde kalabilir; gövde içeriği kalmamalı",
    "Open the message source (“Show original”).": "İleti kaynağını açın (“Özgününü göster”).",
    "Copy into a local editor (Notepad, VS Code, etc.).": "Yerel bir editöre kopyalayın (Notepad, VS Code vb.).",
    "Search and replace personal emails, names, and subject text with placeholders.": "Kişisel e-postaları, adları ve konu metnini yer tutucularla değiştirin.",
    "Delete everything after the first blank line if you only need headers.": "Yalnızca başlık gerekiyorsa ilk boş satırdan sonrasını silin.",
    "Paste the cleaned text into the Header Analyzer.": "Temiz metni Başlık Analizörü’ne yapıştırın.",
}

TOOLS_TR: dict[str, dict[str, str]] = {
    "mx": {
        "name": "MX Sorgusu",
        "desc": "Posta sunucularını bulun ve IP’lerini çözümleyin.",
    },
    "spf": {
        "name": "SPF Sorgusu",
        "desc": "SPF kayıtlarını ve dahil edilen politikaları inceleyin.",
    },
    "dkim": {
        "name": "DKIM Sorgusu",
        "desc": "Yaygın DKIM seçicilerini bulun ve zincirleri izleyin.",
    },
    "dmarc": {
        "name": "DMARC Sorgusu",
        "desc": "DMARC politikasını, rua/ruf ve hizalama etiketlerini kontrol edin.",
    },
    "headers": {
        "name": "E-posta Başlık Analizi",
        "desc": "Ham başlık/kaynak yapıştırın; anlaşılır, eğitici bir rapor alın.",
        "placeholder": "Tam e-posta kaynağını veya başlıkları buraya yapıştırın…",
    },
    "mailtest": {
        "name": "Mail Tester",
        "desc": "Rastgele bir gelen kutusu alın, ileti gönderin, teslimat puanını görün.",
    },
    "dns": {
        "name": "DNS Sorgusu",
        "desc": "A, AAAA, CNAME, NS, TXT, SOA, CAA, MX ve SRV sorgulayın.",
    },
    "ns": {
        "name": "NS Sorgusu",
        "desc": "Bir alanın yetkili ad sunucularını listeleyin.",
    },
    "caa": {
        "name": "CAA Sorgusu",
        "desc": "Hangi CA’ların sertifika verebileceğini görün.",
    },
    "whois": {
        "name": "WHOIS",
        "desc": "Alan veya IP kayıt verilerini sorgulayın.",
    },
    "ssl": {
        "name": "SSL Kontrolü",
        "desc": "Bir kerede en fazla 10 sertifikayı tabloda kontrol edin.",
    },
    "http": {
        "name": "HTTP Başlıkları",
        "desc": "Durum kodunu ve yanıt başlıklarını alın.",
    },
    "port": {
        "name": "Port Kontrolü",
        "desc": "Bir sunucuda TCP portunun açık olup olmadığını test edin.",
    },
    "rdns": {
        "name": "Ters DNS",
        "desc": "Bir IP için PTR kayıtlarını çözümleyin.",
    },
    "blacklist": {
        "name": "Kara Liste Kontrolü",
        "desc": "Bir IP’yi yaygın DNSBL / RBL listelerinde kontrol edin.",
    },
    "smtp": {
        "name": "SMTP Testi",
        "desc": "25. portta SMTP banner, EHLO ve STARTTLS test edin.",
    },
    "exchange": {
        "name": "Microsoft Exchange Server HC",
        "desc": "Dışarıdan Exchange sağlık kontrolü: VD’ler, NTLM vs OAuth 2.0, hybrid/Teams rehberi, TLS.",
        "placeholder": "mail.ornek.com",
    },
    "ip": {
        "name": "IP Sorgusu",
        "desc": "Herkese açık IP’nizi görün (curl uyumlu) veya başka bir IP inceleyin.",
        "placeholder": "kendi IP’niz için boş bırakın",
    },
}

JS_TR: dict[str, str] = {
    "Looking up…": "Sorgulanıyor…",
    "Scanning Exchange endpoints…": "Exchange uç noktaları taranıyor…",
    "External health report": "Dışarıdan sağlık raporu",
    "Virtual directories": "Sanal dizinler",
    "Findings": "Bulgular",
    "TLS certificate": "TLS sertifikası",
    "Related hosts": "İlgili sunucu adları",
    "NTLM": "NTLM",
    "OAuth": "OAuth",
    "OAuth 2.0": "OAuth 2.0",
    "Basic": "Basic",
    "Healthcheck open": "Healthcheck açık",
    "Reachable": "Erişilebilir",
    "closed": "kapalı",
    "open": "açık",
    "auth_required": "kimlik ister",
    "redirect": "yönlendirme",
    "Recommend closing healthchecks to the public internet.": "Healthcheck URL’lerini internete kapatmanız önerilir.",
    "Authentication audit": "Kimlik doğrulama denetimi",
    "Hybrid & Teams guidance": "Hybrid ve Teams rehberi",
    "Microsoft references": "Microsoft referansları",
    "Checked": "Kontrol edildi",
    "Detected": "Saptandı",
    "Not detected": "Saptanmadı",
    "Guidance": "Öneri",
    "How we checked": "Nasıl kontrol ettik",
    "HTTP headers": "HTTP header’lar",
    "Header leaks": "Header sızıntısı",
    "Server name, version, or internal IP in headers is risky.": "Header’da sunucu adı, sürüm veya iç IP risklidir.",
    "No sensitive headers found": "Hassas header bulunamadı",
    "Same frontend IP": "Aynı frontend IP",
    "Request failed": "İstek başarısız",
    "Lookup failed": "Sorgu başarısız",
    "No record": "Kayıt yok",
    "Geolocation unavailable": "Konum bilgisi yok",
    "Sending server": "Gönderen sunucu",
    "Could not create test": "Test oluşturulamadı",
    "Test not found": "Test bulunamadı",
    "Sending…": "Gönderiliyor…",
    "Could not send report.": "Bildirim gönderilemedi.",
    "Network error — please try again.": "Ağ hatası — lütfen tekrar deneyin.",
    "Thanks — your report was sent.": "Teşekkürler — bildiriminiz gönderildi.",
    "Pasted from clipboard.": "Panodan yapıştırıldı.",
    "Clipboard permission denied. Allow clipboard access for this site, then try Paste again.": "Pano izni reddedildi. Bu site için panoya izin verin, sonra Yapıştır’ı tekrar deneyin.",
    "One-click paste needs HTTPS. Open {url}": "Tek tıkla yapıştırma HTTPS ister. Açın: {url}",
    "Address copied. Send your test email now…": "Adres kopyalandı. Test e-postanızı şimdi gönderin…",
    "Copied": "Kopyalandı",
    "Copy": "Kopyala",
    "Waiting for your message…": "İletiniz bekleniyor…",
    "Message received — analyzing…": "İleti alındı — analiz ediliyor…",
    "Nothing to copy": "Kopyalanacak bir şey yok",
    "Clipboard paste needs HTTPS or Ctrl+V": "Pano yapıştırma HTTPS veya Ctrl+V ister",
    "Error": "Hata",
    "Clipboard is empty.": "Pano boş.",
    "Creating test address…": "Test adresi oluşturuluyor…",
    "This test expired. Create a new address.": "Bu testin süresi doldu. Yeni bir adres oluşturun.",
    "No address to copy yet.": "Henüz kopyalanacak adres yok.",
    "Copy blocked — address selected, press Ctrl+C / Cmd+C.": "Kopyalama engellendi — adres seçildi, Ctrl+C / Cmd+C kullanın.",
    "Sent. Thank you!": "Gönderildi. Teşekkürler!",
    "Loading map…": "Harita yükleniyor…",
    "No visitor data yet.": "Henüz ziyaretçi verisi yok.",
    "Could not load visitor map.": "Ziyaretçi haritası yüklenemedi.",
    "visitors": "ziyaretçi",
    "countries": "ülke",
    "Top countries": "Öne çıkan ülkeler",
    "queries": "sorgular",
    "Scanning Exchange endpoints…": "Exchange uç noktaları taranıyor…",
    "External health report": "Dışarıdan sağlık raporu",
    "Virtual directories": "Sanal dizinler",
    "Findings": "Bulgular",
    "TLS certificate": "TLS sertifikası",
    "Related hosts": "İlgili sunucu adları",
    "NTLM": "NTLM",
    "OAuth": "OAuth",
    "Healthcheck open": "Healthcheck açık",
    "Reachable": "Erişilebilir",
    "closed": "kapalı",
    "open": "açık",
    "auth_required": "kimlik ister",
    "redirect": "yönlendirme",
    "error": "hata",
    "Recommend closing healthchecks to the public internet.": "Healthcheck URL’lerini internete kapatmanız önerilir.",
}


def detect_lang() -> str:
    explicit = (request.args.get("lang") or "").lower()
    if explicit in SUPPORTED:
        return explicit
    cookie = (request.cookies.get(COOKIE) or "").lower()
    if cookie in SUPPORTED:
        return cookie
    best = request.accept_languages.best_match(SUPPORTED)
    return best or DEFAULT


def get_lang() -> str:
    return getattr(g, "lang", DEFAULT)


def _(text: str, **kwargs) -> str:
    lang = get_lang()
    out = text
    if lang == "tr":
        out = TR.get(text, text)
    if kwargs:
        try:
            out = out.format(**kwargs)
        except (KeyError, ValueError):
            pass
    return out


def localize_tools(tools: list[dict]) -> list[dict]:
    lang = get_lang()
    if lang != "tr":
        return tools
    localized = []
    for tool in tools:
        item = dict(tool)
        tr = TOOLS_TR.get(tool["slug"]) or {}
        if "name" in tr:
            item["name"] = tr["name"]
        if "desc" in tr:
            item["desc"] = tr["desc"]
        if "placeholder" in tr:
            item["placeholder"] = tr["placeholder"]
        localized.append(item)
    return localized


def js_bundle() -> dict[str, str]:
    """English keys mapped to current-language values for the frontend."""
    lang = get_lang()
    if lang != "tr":
        return {k: k for k in JS_TR}
    return dict(JS_TR)
