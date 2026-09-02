# Wireshark Hub

*[English](README.en.md)*

Wireshark görüntüleme filtresi ve paket analizi referansı.

**→ [Canlı: altanmelihhh-web.github.io/wireshark-filter-hub/](https://altanmelihhh-web.github.io/wireshark-filter-hub/)**

Sahada tekrar tekrar ihtiyaç duyulan komutları tek bir aranabilir sayfada
toplayan bir referans. Her kayıt komutun kendisini, ne işe yaradığını ve ne
zaman kullanılacağını içerir — arama sonucunu tarayıp doğru olanı bulmak yerine
doğrudan çalıştırılabilir olanı verir.

| | |
|---|---|
| Filtre | 490 |
| Kategori | 23 |
| Senaryo | 5 |
| Cheat sheet | 21 |
| Bağımlılık | yok — tek sayfa, tamamen istemci tarafında |
| Ağ çağrısı | yok |

## Kapsam

- ARP
- DHCP
- DNS
- Ethernet
- Expert
- F5
- Genel
- Güvenlik
- HTTP
- HTTP/2
- ICMP
- IP
- Port
- RTP
- Routing
- SIP
- Servisler
- TCP
- TCP Flags
- TLS
- Timeout
- UDP
- VLAN/MPLS

## Kullanım

Sayfayı açın ve arayın. Filtreleme anlık; kategori başlıklarından da
gezinebilirsiniz. Komutlar tek tıkla kopyalanır.

Yerelde çalıştırmak için ekstra bir şey gerekmez:

```bash
git clone https://github.com/altanmelihhh-web/wireshark-filter-hub.git
cd wireshark-filter-hub
python3 -m http.server 8000    # ya da index.html'i doğrudan açın
```

Derleme adımı, paket yöneticisi veya arka uç yoktur — `index.html`, `app.js`,
`style.css`.

## Not

Tüm örneklerdeki adresler dokümantasyon içindir (RFC 5737 / RFC 1918) ve
kurgusaldır. Komutları kendi ortamınızda uygulamadan önce etkisini
değerlendirin; bazıları yapılandırmayı değiştirir veya trafiği etkiler.

## Lisans

MIT — bkz. [LICENSE](LICENSE).
