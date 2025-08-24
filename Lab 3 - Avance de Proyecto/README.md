Apache Modules Lab — Instalación, configuración y pruebas automatizadas de módulos de Apache (seguridad y rendimiento) en Debian/Ubuntu y Docker.
Este repo contiene:
•	setup_apache_modules.sh — script integral que instala, configura y valida módulos (headers, ssl, http2, deflate, expires, cache_disk, remoteip, status, proxy, rewrite, security2/OWASP CRS, evasive) y genera reportes antes vs. después.
•	Dockerfile — imagen lista para levantar Apache con los módulos configurados y que permite ejecutar las pruebas dentro del contenedor.
________________________________________
📦 Módulos incluidos
•	Seguridad: ssl, headers (HSTS/CSP/XFO/XCTO), security2 (ModSecurity + OWASP CRS si está disponible), evasive (anti‑DoS básico), remoteip (log real IP tras proxy), rewrite (HTTP→HTTPS), status (solo localhost).
•	Rendimiento: http2, deflate (gzip), expires (cache-control), cache, cache_disk, proxy/proxy_http (para pruebas de reverse proxy).
El script deja contenido de prueba en /var/www/html y un backend simple en :8080 para validar mod_proxy.
________________________________________
🧪 ¿Qué pruebo y qué reporta?
Se generan dos archivos:
•	Markdown: /root/apache_module_tests_report.md (explicativo y legible)
•	CSV: /root/apache_module_tests_results.csv (métricas comparables)
Pruebas clave:
•	mod_headers: presencia de HSTS, CSP, X-Frame-Options, X-Content-Type-Options.
•	mod_deflate: bytes descargados de test.txt con/ sin compresión.
•	mod_expires: encabezado Expires para estáticos.
•	mod_cache_disk: latencia 1º vs 2º request (miss→hit) con curl.
•	mod_http2: comparación ab (HTTP/1.1) vs h2load (HTTP/2).
•	mod_remoteip: IP de cliente en access log con X-Forwarded-For.
•	ModSecurity (OWASP CRS): benigno /?id=1 vs inyección /?id=1%20OR%201=1 (esperado 403/406 con CRS).
•	mod_evasive: stress con ab para intentar bloqueo.
•	mod_proxy: GET /backend vía reverse proxy → backend Python 8080.
•	mod_status: /server-status?auto (acceso local).
•	mod_rewrite: 301 de HTTP a HTTPS.
⚠️ Estas pruebas son para laboratorio/VM. Evita mod_evasive y WAF en producción sin ajuste fino.
________________________________________
✅ Requisitos
•	Debian/Ubuntu con sudo y acceso a APT.
•	Puerto 80/443 libres.
•	Internet (para paquetes y, opcionalmente, OWASP CRS).
________________________________________
🚀 Uso local (Debian/Ubuntu)
1.	Da permisos y ejecuta:
sudo bash setup_apache_modules.sh all
# o por pasos
# sudo bash setup_apache_modules.sh setup
# sudo bash setup_apache_modules.sh test
2.	Ver reportes:
sudo less /root/apache_module_tests_report.md
sudo column -s, -t /root/apache_module_tests_results.csv | less -S
El script crea un certificado self‑signed, habilita HTTP/2 y configura headers seguros.
________________________________________
🐳 Uso con Docker
Construir imagen
docker build -t apache-modules-lab .
Ejecutar contenedor
docker run -d \
  --name apachelab \
  -p 8080:80 -p 8443:443 \
  apache-modules-lab
Visita: http://localhost:8080/ y https://localhost:8443/ (self‑signed).
Correr pruebas dentro del contenedor
docker exec -it apachelab bash -lc \
  "/usr/local/bin/setup_apache_modules.sh test && echo '---'; tail -n +1 /root/apache_module_tests_report.md | sed -n '1,200p'"
Los archivos de reporte quedan dentro del contenedor en /root/.
Si necesitas sacar los reportes: docker cp apachelab:/root/apache_module_tests_report.md ./.
________________________________________
🧰 Estructura sugerida del repo
.
├── Dockerfile
├── README.md
└── setup_apache_modules.sh
________________________________________
🔧 Solución de problemas
•	OWASP CRS no se instala: depende del repo de tu distro. El script sigue funcionando con configuración base de ModSecurity y lo indicará en el reporte. Si quieres CRS sí o sí, instala manualmente desde paquete o upstream.
•	HTTP/2 (h2load) falta: se instala con nghttp2-client. Verifica h2load -v.
•	mod_evasive no bloquea: ajusta thresholds en /etc/apache2/mods-available/evasive.conf (valores más agresivos) y re‑carga Apache.
•	En Docker: el servicio corre con apachectl -D FOREGROUND. El script mapea internamente comandos systemctl a apachectl dentro del contenedor.
________________________________________
⚠️ Seguridad
•	No expongas /server-status fuera de localhost.
•	Ajusta CSP a tu aplicación real.
•	ModSecurity en Blocking Mode puede causar falsos positivos; revisa logs antes de producción.
________________________________________
