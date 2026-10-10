# Electron Cash Docker v1.0 — Guía de usuario

[English](USER-GUIDE.md) · [README](../README.md) · [Seguridad](../SECURITY.md)

## Qué es Electron Cash Docker

Con Electron Cash Docker (ECD) puedes utilizar Electron Cash 4.4.6, una cartera
de Bitcoin Cash (BCH), en un equipo que controlas tú: crear o recuperar una
cartera, recibir BCH y revisar y enviar pagos. Docker reúne la aplicación y sus
dependencias; Docker Compose compila y pone en marcha los servicios necesarios.

Está pensado para quienes se manejan instalando Docker, editando un archivo de
configuración y ejecutando comandos, y quieren una instalación reproducible.
Lo habitual es acceder **desde el navegador del mismo equipo**. noVNC muestra
la aplicación de escritorio de Electron Cash: la cartera se ejecuta en el
contenedor, no en el navegador. También puedes optar por una ventana nativa
o por automatización.

Los datos se conservan en un volumen Docker, pero **ese volumen no es una copia
de seguridad**. Guarda la semilla sin conexión y haz copias cifradas por separado.
La contraseña de acceso web, la de cifrado de la cartera y la de la copia
protegen cosas distintas. Docker no protege la cartera frente a un equipo
comprometido ni frente a su administrador. Tor y CashFusion manual están
disponibles, pero no garantizan el anonimato.

Esta guía corresponde al **candidato de v1.0**. Que esté preparado localmente
no significa que se haya publicado: el repositorio público puede no incluir
sus cambios. Consulta las [notas de versión](../CHANGELOG.md#v10) y, para usar
el candidato, parte de la copia del código o del paquete revisado correspondiente.

### Busca lo que necesitas

- [Elegir la instalación](#elegir-la-instalación)
- [Instalar, acceder y crear la primera cartera](#instalación-y-primer-inicio)
- [Uso diario y cierre](#uso-diario-y-cierre)
- [Preferencias, privacidad y plugins](#preferencias-privacidad-y-plugins)
- [Copia, restauración y recuperación](#copia-restauración-y-recuperación)
- [Otras formas de acceso](#otras-formas-de-acceso)
- [Actualización y diagnóstico](#diagnóstico-y-actualización)
- [Probar sin fondos](#probar-sin-fondos)
- [Opciones técnicas y límites](#opciones-técnicas-y-límites)

## Elegir la instalación

Para una cartera personal, empieza con el **navegador en el mismo equipo**.
Docker y el navegador deben estar en ese ordenador: la dirección de bucle local
predeterminada no acepta conexiones desde otros equipos. Elige otra modalidad
cuando necesites sus funciones. El acceso remoto exige configurar HTTPS expresamente.

| Equipo o necesidad | Modalidad |
|---|---|
| Linux, macOS o Windows con Docker disponible | Navegador local; sigue el inicio rápido de abajo |
| Escritorio Linux con X11/XWayland | [Ventana nativa](#gui-nativa-y-ledger) con el archivo Compose de GUI |
| Escritorio macOS | [Ventana nativa](#gui-nativa-y-ledger) con Docker Desktop y XQuartz |
| Escritorio Windows | Navegador; no hay una modalidad de ventana nativa admitida |
| Cartera física Ledger | [Solo Docker Engine nativo de Linux](#gui-nativa-y-ledger), con los archivos de GUI y hardware |
| Automatización sin ventana | [Servicio headless](#headless-y-rpc); JSON-RPC se activa por separado |
| Navegador en otro ordenador | [Acceso remoto protegido](#acceso-local-y-remoto-protegido) |

Necesitas Docker Engine 20.10+ y Compose 2.24+ (los archivos adicionales usan
`!reset`), al menos 2 GiB de memoria disponible y unos 2 GiB para las imágenes.
Reserva más espacio y memoria para compilar desde cero; el tiempo depende de
las descargas y del equipo. Docker Desktop proporciona el entorno Docker de
la modalidad documentada de macOS y del acceso por navegador en Windows,
con contenedores Linux. XQuartz solo hace falta para la ventana nativa de macOS.

Ejecuta los comandos desde la raíz del repositorio. El inicio rápido usa un
terminal POSIX en Linux/macOS. En Windows puedes usar PowerShell, con el comando
de copia indicado abajo, o WSL/Git Bash con acceso a Docker. Los comandos Docker
sin asignaciones de variables sirven en ambos terminales. Los scripts Linux
siguen necesitando el entorno Linux documentado; disponer de Bash en Windows
no hace compatibles todas las modalidades Linux.

Usa el mismo proyecto Compose y los mismos archivos adicionales (overlays) al
iniciar, detener, hacer copias y actualizar. Si prefieres familiarizarte con la
aplicación antes de crear una cartera real, sigue la [prueba Chipnet separada](#probar-sin-fondos).

## Instalación y primer inicio

Estos pasos inician el acceso por navegador local en **mainnet**, la red de BCH
real. Para practicar, sigue la prueba Chipnet aislada en lugar de convertir
esta instalación en una demostración.

1. Obtén el código de la versión que quieres utilizar. Con Git instalado,
   estos comandos descargan el repositorio público y te sitúan en su raíz:

   ```bash
   git clone https://gitlab.com/bchforge/electron-cash-docker
   cd electron-cash-docker
   ```

   Si el candidato aún no está publicado, abre la copia revisada que hayas
   recibido. Clonar el repositorio no basta para obtener sus cambios de v1.0.

2. Crea `.env`, el archivo de ajustes locales. **Omite este paso si ya existe**
   para no sobrescribir tu configuración. En un terminal POSIX de Linux/macOS:

   ```bash
   cp .env.example .env
   ```

   En PowerShell de Windows, utiliza esto en lugar de `cp`:

   ```powershell
   Copy-Item .env.example .env
   ```

3. Abre `.env` en un editor de texto local y establece una `BASIC_AUTH_PASSWORD`
   robusta y exclusiva. Es la **contraseña de acceso web**, no la de cifrado de
   la cartera. La plantilla la deja vacía: debes definirla antes de iniciar.
   Escribe `$$` para representar un `$` literal en valores dotenv de Compose
   sin comillas. Para el uso local habitual, conserva estos ajustes:

   | Ajuste | Valor para uso local |
   |---|---|
   | `NETWORK` | `mainnet` |
   | `CADDY_EDGE_BIND` | `127.0.0.1` |
   | `CADDY_SITE_ADDRESS` | `localhost` |
   | `WALLET_AUTO_CREATE` | `false` — crea la cartera en Electron Cash |
   | `JSONRPC_ENABLED` | `false` |

   Nunca pongas una semilla ni la contraseña de una cartera real en `.env`,
   comandos o registros. Aunque Git ignore `.env`, sigue siendo un archivo
   sensible. Protégelo; la salida de Compose con valores resueltos también
   puede revelar sus secretos.

4. Compila e inicia (estos comandos Docker también sirven en PowerShell):

   ```bash
   docker compose build --pull
   docker compose up -d
   docker compose ps
   ```

   Espera a que los servicios estén listos. La primera compilación descarga
   dependencias verificadas y puede tardar más que los siguientes inicios.

5. Abre **`http://127.0.0.1/`** en ese equipo. Introduce la contraseña web y pulsa
   **Connect**; no se pide usuario. Deja **Remember this session** sin marcar
   para un acceso breve; márcalo únicamente en un dispositivo de confianza.
   Aparecerá Electron Cash y, si el volumen es nuevo, su asistente de cartera.

   Si el puerto 80 está ocupado, define `CADDY_HTTP_HOST_PORT=18080` (u otro
   puerto libre), ejecuta de nuevo `docker compose up -d` y abre
   `http://127.0.0.1:18080/`. Conserva `CADDY_EDGE_BIND=127.0.0.1`.
   Si la página no está lista, consulta el [diagnóstico por síntomas](#diagnóstico-por-síntomas).

### Crear o recuperar tu primera cartera

Utiliza el asistente de **Electron Cash**, no el formulario de acceso web.
Pon a la cartera un nombre que puedas reconocer y elige la opción que corresponda:

- **Cartera nueva:** para una cartera personal habitual, elige el tipo estándar
  y genera una semilla nueva. Anota las palabras en orden en papel u otro soporte
  sin conexión. Guarda esa copia
  en un lugar privado, protegido frente a pérdidas o daños y separado de este
  equipo. Completa la comprobación de la semilla que pide el asistente **antes
  de recibir fondos**. Quien obtenga la semilla puede controlar la cartera;
  poner una contraseña no invalida una semilla que ya se haya divulgado.
- **Cartera existente:** elige recuperar o importar e introduce la semilla o
  las claves directamente en el campo correspondiente, en un equipo de confianza.
  Sigue el asistente según el tipo de cartera. Si utilizaste una extensión de
  semilla o frase de derivación, consérvala e introdúcela también: no es la
  contraseña de cifrado de la cartera. Si tienes un archivo `.ecd.gpg`,
  el procedimiento es distinto: consulta [Restaurar una copia](#restaurar-una-copia).

Establece una contraseña de cifrado antes de usar fondos importantes y termina
el asistente. Comprueba la red y el estado de conexión antes de usar la cartera.
No incluyas semillas, claves privadas ni contraseñas en solicitudes de ayuda,
capturas, el portapapeles del navegador o herramientas de prueba compartidas.
Los nombres de las opciones pueden variar según el idioma y el tipo de cartera.

Cada secreto cumple una función distinta:

| Secreto | Qué protege o recupera |
|---|---|
| `BASIC_AUTH_PASSWORD` | El acceso al escritorio desde el navegador |
| Contraseña de la cartera | Los datos privados cifrados y las operaciones autorizadas por la cartera |
| Semilla de recuperación | Las claves de la cartera; quien la tenga puede controlar los fondos |
| Contraseña de la copia | El descifrado del archivo `.ecd.gpg` |

La semilla recupera las claves de la cartera correspondiente, pero no
necesariamente etiquetas, otros metadatos o ajustes de plugins. Una cartera de
claves importadas o de solo lectura puede no tener semilla: conserva el material
de recuperación original que corresponda a su tipo. Guarda también una copia
cifrada, además de ese material de recuperación independiente y sin conexión.

## Uso diario y cierre

### Recibir y enviar BCH

**Para recibir:** abre la cartera correcta en Electron Cash y utiliza su vista
de recepción para obtener una dirección. Comprueba la red y comparte la dirección
o su código QR con quien vaya a pagarte. Consulta el historial para ver la llegada
de la transacción y sus confirmaciones. Una dirección de una red de prueba no
es un destino de pago en mainnet.

**Para enviar:** utiliza la vista de envío, introduce la dirección BCH del
destinatario y el importe, y revisa destino, red, cantidad y comisión antes de
aprobar. Desbloquea la cartera cifrada cuando lo solicite. Por ejemplo, para
pagar una factura de `0.001 BCH`, comprueba que el importe está expresado en BCH,
no en otra unidad de visualización. Tras transmitir la transacción, consulta
su estado y confirmaciones en el historial. Cerrar la pestaña no cancela un pago
que ya se ha transmitido a la red.
Una cartera de solo lectura no puede firmar pagos: necesitas las claves privadas
o el dispositivo de firma correspondiente, no solo una dirección o clave pública.

### Dónde se guardan los datos

El volumen Docker predeterminado se llama `bchforge-electron-cash-data` y se
monta en `/home/electroncash/.electron-cash`. Es un espacio de almacenamiento
gestionado por Docker: los archivos y la configuración de la cartera se conservan
al reiniciar o recrear contenedores y al ejecutar `docker compose down`.
**Un volumen persistente no es una copia de seguridad. Nunca uses
`down --volumes` con datos reales.** Vuelve a la cartera con el mismo volumen y proyecto.

### Cerrar y reiniciar una sesión GUI del navegador

Cerrar una pestaña desconecta ese navegador, pero no cierra la cartera.
En Electron Cash 4.4.6, **File > Quit / Ctrl+Q cierra la ventana de cartera actual**.
Cerrar la ventana conserva su archivo. **File > Delete** elimina el archivo
seleccionado tras las confirmaciones, comprobaciones de contraseña y diálogo
de finalización de Electron Cash; no sirve para cerrar una ventana. Cancelar
la eliminación o que esta falle no termina por sí solo la sesión.

La aplicación continúa mientras quede otra cartera abierta, aunque esté
minimizada u oculta, o un diálogo activo para abrir, crear o recuperar una.
Al cerrar la última cartera y terminar o cancelar el último asistente,
**se detiene el proyecto de navegador predeterminado**: Electron Cash, los
servicios web (auth-session, Caddy y fail2ban) y Tor. noVNC muestra que la sesión
ha terminado y deja de intentar reconectar. Los proyectos headless/RPC
independientes siguen funcionando; las modalidades nativas tienen sus propias
instrucciones de parada.

Para volver a entrar, ejecuta:

```bash
docker compose up -d
```

Deja abierta la misma pestaña: recuperará el escritorio si la cookie y la sesión
web del servidor siguen siendo válidas; si no, volverá al acceso. Tras una
interrupción, deja unos 35 segundos desde que los servicios estén listos, más
el tiempo de carga de la página. Terminar la aplicación **no cierra la sesión web**.
Las carteras cerradas conservan sus datos; las eliminadas no se recrean. Si
no queda ninguna, el inicio ofrece el asistente habitual para abrir o crear una.

Para detener el proyecto desde el terminal sin eliminar contenedores:

```bash
docker compose stop
```

`docker compose start` inicia los contenedores existentes. Usa preferentemente
`up -d` si la aplicación ha terminado la sesión o has cambiado la configuración.
Para eliminar los contenedores conservando los volúmenes persistentes:

```bash
docker compose down
```

Los fallos temporales de conexión permiten reconectar. Si la cartera falla
inesperadamente, tiene reintentos limitados por `on-failure:5`; un estado
unhealthy por sí solo no provoca un reinicio automático.

### Acceso web y duración de la sesión

El navegador conserva una cookie HTTP; el servidor guarda la sesión por separado
de los datos de cartera. Sin **Remember this session**, el acceso caduca
**30 minutos después de iniciar sesión**. Al marcarlo, puede durar hasta
**30 días**. Usar la cartera no amplía ninguno de esos plazos. Cerrar la pestaña,
Electron Cash o los contenedores no revoca por sí solo el acceso web.

Para una sesión temporal, volver a la dirección raíz del sitio `/` la elimina
y muestra el formulario. Una sesión recordada válida, en cambio, vuelve al
escritorio. La [referencia de sesiones](#referencia-de-sesiones-web) explica el
endpoint de cierre y las demás reglas de caducidad y revocación. Cambiar la
contraseña web y recrear invalida las sesiones anteriores. Las copias de cartera
no incluyen sesiones web. No confíes en cerrar el navegador para borrar la
cookie: algunos la recuperan al abrirse de nuevo.

### Escribir en la cartera

Haz clic en el campo correcto de Electron Cash antes de escribir. Los atajos
del navegador o del sistema pueden interceptar teclas; la barra de noVNC ofrece
teclas adicionales y solicita un teclado en pantalla cuando es compatible.
Comprueba qué campo está activo al cambiar de ventana. Para distribuciones,
modificadores atascados y entrada virtual, consulta el
[teclado del navegador](#teclado-del-navegador). Nunca pegues una semilla en el
portapapeles; la entrada virtual no protege un equipo comprometido.

## Preferencias, privacidad y plugins

### Idioma y apariencia

Electron Cash se inicia en inglés por defecto (`EC_LANGUAGE=en_US`). Para una
**configuración nueva**, establece `EC_LANGUAGE` en `.env` con cualquier código
de idioma admitido por la versión fijada de Electron Cash. Se admiten los 38
códigos oficiales de EC 4.4.6; un valor vacío (`EC_LANGUAGE=`) selecciona Sistema. Solo los
códigos inválidos impiden el inicio antes de inicializar la cartera. Los volúmenes
existentes conservan el idioma guardado, incluso Sistema o una clave histórica
ausente. Cambia el idioma en Preferencias de Electron Cash: se conserva tras
reiniciar y el login ECD lo refleja al recargar, sin reiniciar el contenedor.
Se admiten variantes regionales y RTL; la documentación sigue solo en EN/ES.
`DARK_MODE=true` activa el tema oscuro nativo. Si falta, está vacío o vale
`false`, se aplica el tema claro y se elimina una preferencia oscura guardada.
Se ignoran los espacios de los extremos y las diferencias entre mayúsculas
y minúsculas; se rechazan los valores distintos de true/false.

Después de editar `.env`, recrea con `docker compose up -d` y los mismos archivos
adicionales que use tu instalación. `restart` mantiene el entorno antiguo del
contenedor. El idioma solo inicializa configuraciones nuevas, también en ventanas
nativas y headless; el tema se aplica en cada inicio y sustituye el tema guardado.
Los cambios de tema hechos en la interfaz pueden durar la sesión actual.
Estas opciones no modifican `LANG`, `LC_ALL`, `LANGUAGE`
ni los controles de noVNC; headless no tiene interfaz gráfica.

### Tor y CashFusion

Tor puede reducir la exposición de tu dirección IP ante los servidores de
cartera. No oculta los archivos de cartera ni protege un equipo comprometido.
`USE_TOR=true` envía el tráfico SPV configurado de Electron Cash (sus conexiones
con servidores) a través de `socks5:tor-proxy:9050`. CashFusion utiliza ese Tor
interno. Esto **no** pasa por Tor el navegador, el equipo ni todos los plugins.
`USE_TOR=false` desactiva el proxy SPV. Que el servicio SOCKS local esté listo
no garantiza poder conectar con servidores externos.

CashFusion busca dificultar el análisis de vínculos entre transacciones al
combinar monedas aptas con las de otros participantes. Está instalado
y disponible con `CASHFUSION_ENABLED=true`, pero
`CASHFUSION_AUTO_FUSE=false` deja desactivada la participación automática por
defecto. Empieza por los controles manuales de la interfaz; las carteras cifradas
siguen necesitando su desbloqueo habitual. Para desactivar el plugin, establece
`CASHFUSION_ENABLED=false`. No se garantiza disponer de servidor, monedas aptas,
una ronda completada ni anonimato. Puede no haber servicios de fusión en redes
de prueba; el ensayo Chipnet de abajo no debe iniciar ninguna ronda.

Los ajustes iniciales solo rellenan preferencias que aún no existen: lo que
cambies en la interfaz se conserva al reiniciar, igual que el idioma, pero a
diferencia del tema. El perfil inicial usa profundidad 3 y selección por cantidad con objetivo
de 10 monedas; no promete completar rondas ni obtener una cantidad final exacta.
La participación automática sigue desactivada. Consulta la
[referencia de CashFusion](#controles-de-cashfusion) para cambiar selectores,
rondas en cola o límites independientes de comisiones y entradas. Los ajustes
inválidos impiden arrancar antes de modificar la configuración.

### Elegir la red correcta

Conserva `NETWORK=mainnet` para BCH real. Las demás redes tienen datos de
cartera y configuración separados en el volumen; cambiar de red puede mostrar
otra cartera o una vacía. Define `NETWORK` en `.env` y recrea con los mismos
archivos de modalidad. Haz copias y restaura con la red correspondiente.
La [referencia de redes](#redes-y-ciclo-de-vida) recoge los valores admitidos
y sus restricciones; para practicar sin fondos, sigue la
[prueba Chipnet aislada](#probar-sin-fondos).

### Plugins

**Flipstarter Helper** se incluye como plugin del escritorio Qt; no es una
interfaz headless de Flipstarter. Los plugins se verifican al compilar y al
iniciar, y no se descargan durante el uso. Cambiar uno exige revisar su código
y volver a compilar; consulta la [procedencia de los plugins](#procedencia-de-los-plugins).

## Copia, restauración y recuperación

La semilla o las claves originales permiten recuperar las claves de la cartera;
el archivo cifrado permite recuperar los archivos y metadatos guardados de la
red seleccionada. Necesitas conservar ambos. Guarda las copias en otro soporte
seguro, fuera del equipo Docker, y su contraseña por separado.
**Comprueba la recuperación en una instalación aislada antes de confiar en una copia.**

El archivo recoge el estado de cartera de la red elegida, no toda la instalación.
Conserva `.env` y los ajustes de instalación en otro lugar seguro; las credenciales
RPC se eliminan de la configuración archivada y no se incluye el almacenamiento
de autenticación web.

En Linux se utiliza `scripts/backup.sh`; Windows dispone de `scripts/backup.ps1`.
El script POSIX se ha validado en Linux. Su comprobación de permisos con GNU
`stat -c` hace que la recuperación desde un host macOS no sea una modalidad
demostrada; disponer de escritorio macOS no implica soporte del script de copia
y restauración en ese host.

Ambos scripts necesitan Docker/Compose, la imagen de cartera compilada y un
volumen de cartera seleccionado que ya exista. Haz coincidir `COMPOSE_FILE`,
`COMPOSE_PROJECT_NAME`, `ECD_WALLET_VOLUME` y `NETWORK` con la instalación,
incluidos los archivos adicionales de modalidad. La imagen auxiliar se elige
por `IMAGE` en el entorno del host, después `ELECTRON_CASH_IMAGE` y, por último,
`electron-cash:<EC_VERSION>`; no selecciona automáticamente `ECD_HW_IMAGE`.
Para hacer copias en modalidad Ledger, define `IMAGE` en el host con tu imagen
de hardware compilada y conserva los archivos de GUI y hardware. `BACKUP_DIR`
e `IMAGE` son variables de entorno del script: defínelas en el terminal, no solo
en `.env`. No permitas que otra instalación escriba en el mismo volumen.

### Hacer una copia de seguridad

1. Termina las operaciones de la cartera. Desde la raíz del repositorio, elige
   un nombre nuevo para el archivo (letras, números, `.`, `_`, `-`; sin rutas ni `..`):

   ```bash
   ./scripts/backup.sh backup wallet-copy
   ```

   Alternativa en PowerShell de Windows:

   ```powershell
   .\scripts\backup.ps1 backup wallet-copy
   ```

2. Introduce y confirma una contraseña robusta para la copia cuando se solicite.
   No la pases como argumento ni variable de entorno. Si Electron Cash está
   ejecutándose, el script lo detiene temporalmente para obtener una copia
    coherente y, si todo va bien, devuelve ese servicio a su estado previo.
    Si estaba detenido, seguirá detenido. Revisa cualquier error de reinicio:
    que se haya creado el archivo no implica que el servicio haya vuelto a arrancar.
3. Comprueba el mensaje de éxito y conserva **`backups/wallet-copy.ecd.gpg`**.
   `BACKUP_DIR` permite elegir otro destino; usa una ruta absoluta del host.
   No se sobrescribe una copia existente.
   Guarda el archivo cifrado fuera del equipo; usa GPG con AES-256 e incluye
   la red seleccionada, un manifiesto y hashes de los archivos.

Por ejemplo, en una instalación headless de Linux, selecciona sus mismos archivos:

```bash
COMPOSE_FILE=docker-compose.yml:docker-compose.headless.yml ./scripts/backup.sh backup wallet-copy
```

En Windows, define `COMPOSE_FILE` en el entorno con el separador de listas de
archivos de Windows, `;`, y `COMPOSE_PROJECT_NAME` con el proyecto correspondiente
antes de usar el script PowerShell. En otras modalidades, conserva también su
lista completa de archivos.

Por ejemplo, para un proyecto headless llamado `my-wallet`, en PowerShell de Windows:

```powershell
$env:COMPOSE_FILE = 'docker-compose.yml;docker-compose.headless.yml'
$env:COMPOSE_PROJECT_NAME = 'my-wallet'
.\scripts\backup.ps1 backup wallet-copy
```

Sustituye el nombre de ejemplo por tu proyecto real y conserva esa selección
para restaurar. Las variables siguen definidas en ese terminal: abre otro
o elimínalas antes de operar sobre una instalación diferente.

### Restaurar una copia

**La restauración sustituye el estado actual de las carteras de la red elegida.**
No es el paso siguiente a cada copia de seguridad. Ensáyala primero en una
instalación aislada y desechable, con un volumen limpio ya inicializado y sin
carteras reales. Sus volúmenes, proyecto, imágenes y puertos no deben coincidir
con los de la instalación habitual. Conserva la red del archivo y una imagen
con **la misma versión de Electron Cash que figura en la copia**.
Los scripts validan el formato, la red y los
hashes; no convierten formatos de cartera arbitrarios.

1. Guarda una copia del estado actual antes de sustituir datos existentes.
   Coloca el archivo en `backups/` (o el `BACKUP_DIR` elegido) y comprueba proyecto,
   volumen, red y modalidad. Se conservarán los datos de las otras redes.
2. Ejecuta únicamente el comando de restauración de tu sistema:

   ```bash
   ./scripts/backup.sh restore wallet-copy
   ```

   Alternativa en PowerShell de Windows:

   ```powershell
   .\scripts\backup.ps1 restore wallet-copy
   ```

3. Lee el aviso de sustitución, confirma solo si el destino es correcto e
   introduce la contraseña de la copia. Cancelar, equivocarse de contraseña,
   usar un archivo inválido o una red diferente debe dejar intactos los datos
   existentes. El script valida antes de sustituir y guarda el volumen actual
   para poder volver atrás.
4. Comprueba el resultado. Si Electron Cash estaba funcionando, el script lo
   reinicia y comprueba su arranque y estado. **Si estaba detenido, seguirá
   detenido**: en ese caso no fuerza el inicio ni una comprobación de salud.
    Inicia tú la modalidad elegida cuando corresponda, con `docker compose up -d`
    y el mismo proyecto y archivos, y comprueba en Electron Cash la cartera
    recuperada y sus metadatos. Puede seguir haciendo falta la
   contraseña de cifrado de la cartera después de descifrar la copia.

Si falla la sustitución o el arranque posterior, el script intenta recuperar
el estado guardado. Si no puede terminar esa recuperación, conserva el volumen
de recuperación y el registro pendiente e informa del error. Guárdalos junto
con los registros sin secretos; no borres volúmenes ni el registro pendiente,
ni repitas la sustitución a ciegas. En la siguiente ejecución, el script comprueba
si quedó una restauración interrumpida e intenta recuperarla antes de continuar.
Crear correctamente un archivo no demuestra por sí solo que puedas recuperarlo.

## Otras formas de acceso

Elige estas opciones si necesitas acceso remoto, una ventana nativa, hardware
o automatización. Prepara primero `.env` y compila las imágenes necesarias.
Antes de cambiar de modalidad, elimina los contenedores de la actual con su
`down` habitual (sin `--volumes`) e inicia la nueva. Conserva la lista completa
de archivos Compose al iniciar, detener, hacer copias y actualizar. Nunca
ejecutes dos procesos de cartera sobre el mismo volumen ni actives los perfiles
de servicios web en una instalación nativa/headless.

### Acceso local y remoto protegido

Los valores predeterminados son `CADDY_EDGE_BIND=127.0.0.1`, puerto HTTP 80,
puerto HTTPS 443 y `CADDY_SITE_ADDRESS=localhost`. HTTP local no redirige;
HTTPS local utiliza la autoridad de certificación interna de Caddy y necesita
la confianza correspondiente del navegador o sistema. Para conflictos de puertos
usa `CADDY_HTTP_HOST_PORT` / `CADDY_HTTPS_HOST_PORT`. No se admite publicación
directa mediante `NOVNC_BIND`/`NOVNC_HOST_PORT`.

El acceso remoto exige administrar dominio, cortafuegos y certificados:

1. Elige una `BASIC_AUTH_PASSWORD` robusta y exclusiva; conserva la protección
   por sesiones y fail2ban.
2. Define `CADDY_SITE_ADDRESS=wallet.example.com` (solo dominio),
   `CADDY_TLS_MODE=auto`, `CADDY_EDGE_BIND=0.0.0.0` y puertos del host 80/443.
3. Configura tú los registros DNS A/AAAA y la entrada TCP 80/443. La emisión
   del certificado público depende de DNS, conectividad y la autoridad de
   certificación. Recrea el proyecto tras cambiar la configuración.
4. Desde un cliente independiente, comprueba HTTPS válido y la redirección
   HTTP a HTTPS, el rechazo de recursos y conexiones WebSocket sin autenticar,
   y el bloqueo temporal de fail2ban sin afectar a otro cliente.
5. Nunca publiques VNC 5900/noVNC 6080 internos ni RPC sin autenticar. Mantén
   RPC en la dirección local. No desactives la verificación de certificados ni
   cambies sin criterio los rangos de proxies de confianza: las cabeceras
   enviadas por cualquier cliente no acreditan su identidad.

Caddy comprueba la sesión web antes de reenviar el tráfico protegido del escritorio.
La terminología histórica Basic Auth no implica que se necesite un usuario o
el diálogo de autenticación del navegador. Fail2ban admite por defecto cinco
fallos en 600 segundos y bloquea durante 3600 segundos; ignora las direcciones
de bucle local. Los 401 de consultas pasivas de estado no son intentos de adivinar
contraseñas. Con proxies admitidos, el bloqueo puede aplicarse en Caddy en
lugar de descartar paquetes de la IP del cliente final.

### GUI nativa y Ledger

**Ventana nativa en Linux.** Parte de un escritorio local X11/XWayland autenticado.
`DISPLAY` identifica la pantalla; Xauthority es la cookie privada que autoriza
el acceso. Mantén el archivo del host en su ubicación habitual (`XAUTHORITY`
si está definido). El script auxiliar copia la cookie a un volumen privado de
solo lectura. No uses `xhost +` ni cambies el propietario del archivo del host.
Después de compilar las imágenes base:

```bash
test -n "$DISPLAY" &&
docker compose -f docker-compose.yml -f docker-compose.gui.yml up -d
```

Debería abrirse una ventana nativa de Electron Cash, sin noVNC ni servicios web.
Detén la modalidad con los mismos archivos antes de volver al navegador:

```bash
docker compose -f docker-compose.yml -f docker-compose.gui.yml down
```

**Ventana nativa en macOS.** Instala e inicia Docker Desktop y XQuartz. El script
necesita Compose **2.24.4+** para el archivo `!override` que genera. También
requiere Python 3 en el host y `xauth` de XQuartz en el PATH de la shell
(normalmente `/opt/X11/bin`), además de las herramientas habituales de macOS.
Elimina los contenedores y la red de la modalidad actual con su `down` habitual,
sin borrar volúmenes: el script rechaza un proyecto que ya tenga esos recursos.
En **Intel**, tras compilar la imagen base de cartera, ejecuta:

```bash
bash scripts/mac-gui.sh
```

En **Apple Silicon**, selecciona expresamente las plataformas admitidas:
`linux/amd64` bajo emulación para la cartera y `linux/arm64` para Tor. El script
acepta un archivo validado mediante `ECD_PLATFORM_OVERRIDE`; no elige esas
plataformas automáticamente. Este ejemplo POSIX crea un archivo temporal,
compila la imagen de cartera correspondiente, ejecuta el script y elimina
el archivo temporal al salir:

```bash
(
  MAC_PLATFORM_FILE="$(mktemp "${TMPDIR:-/tmp}/ecd-mac-platform.XXXXXXXX")" || exit 1
  trap 'rm -f "$MAC_PLATFORM_FILE"' EXIT
  python3 - "$MAC_PLATFORM_FILE" <<'PY' || exit 1
import json, sys
with open(sys.argv[1], "w") as target:
    json.dump({"services": {
        "electron-cash": {"platform": "linux/amd64"},
        "tor-proxy": {"platform": "linux/arm64"}
    }}, target)
PY
  DISPLAY="${DISPLAY:-:0}" docker compose -f docker-compose.yml -f docker-compose.gui.yml -f "$MAC_PLATFORM_FILE" build electron-cash || exit 1
  ECD_PLATFORM_OVERRIDE="$MAC_PLATFORM_FILE" bash scripts/mac-gui.sh
)
```

El script gestiona temporalmente las cookies y la escucha de pantalla y recupera
la configuración anterior al salir. Termina o cancela los asistentes y cierra
la última ventana de cartera para terminar
el script en primer plano; elimina sus contenedores y conserva los volúmenes
de cartera. Es acceso local al escritorio, no X11 público. La imagen arm64 nativa
de Tor evita sus limitaciones seccomp al emular amd64; no desactives su aislamiento
para sortearlas. La
[validación de plataformas](platform-validation.md) recoge las configuraciones
observadas, los límites de arquitectura nativa y las instrucciones de pantalla
por SSH para mantenimiento.

**Ledger.** Utiliza únicamente Docker Engine nativo de Linux, el archivo de GUI
y `docker-compose.hw.yml`. Define `HW_USB_GID` con el grupo propietario del nodo
USB de Ledger en el host y prepara los permisos necesarios del dispositivo;
consulta [validación de plataformas](platform-validation.md#ledger--native-linux).

```bash
docker compose -f docker-compose.yml -f docker-compose.gui.yml -f docker-compose.hw.yml build electron-cash
docker compose -f docker-compose.yml -f docker-compose.gui.yml -f docker-compose.hw.yml up -d
```

Desbloquea el dispositivo y abre su aplicación BCH **en el propio dispositivo**.
Nunca escribas el PIN o la semilla en el navegador, terminal o registros. Solo
la imagen de cartera con hardware recibe acceso USB; no necesita un contenedor
privilegiado. El componente de Ledger filtra sus identificadores, pero el archivo
adicional expone el bus USB del host Linux, no un único dispositivo. No conectes
otros dispositivos USB sensibles a esa vía. No se afirma compatibilidad con todos
los modelos, otras carteras físicas, Ledger en Docker Desktop ni certificación
de firma de transacciones.

### Headless y RPC

Headless ejecuta el servicio de cartera sin escritorio y está pensado para
quien sabe utilizar la CLI de Electron Cash. Después de compilar, inicia y
espera a que el servicio esté listo:

```bash
docker compose -f docker-compose.yml -f docker-compose.headless.yml up -d --wait
docker compose -f docker-compose.yml -f docker-compose.headless.yml exec --user 10001:10001 electron-cash /opt/electroncash-venv/bin/electron-cash daemon status
```

Para otra red, añade su opción CLI, como `--chipnet`, antes de `daemon status`.
No se ejecutan Xvfb/Openbox/RFB/websockify. La configuración base sigue exigiendo
`BASIC_AUTH_PASSWORD` para resolver Compose, aunque no se inicien los servicios
web. Las carteras reales cifradas requieren carga y desbloqueo por el operador;
`WALLET_AUTO_CREATE` es una función de pruebas desechables solo en Chipnet,
no una forma de preparar una cartera real. Espera a que esté listo antes de
usar la CLI: los comandos prematuros pueden escribir configuración de Electron
Cash mientras se inicializa. Las comprobaciones de inicio y salud utilizan
una consulta local de solo lectura al servicio de cartera.

JSON-RPC permite controlar la cartera desde programas. Está desactivado por
defecto (`JSONRPC_ENABLED=false`) y necesita `JSONRPC_USER` y
`JSONRPC_PASSWORD` **independientes y no vacíos** en `.env`. Solo el archivo
RPC explícito lo activa y publica:

```bash
docker compose -f docker-compose.yml -f docker-compose.headless.yml -f docker-compose.rpc.yml up -d
```

Se publica en `127.0.0.1:50001`; `JSONRPC_HOST_PORT` cambia el puerto del host
y `JSONRPC_PORT`, el interno. El servicio interno también exige autenticación
por contraseña. No pongas credenciales en URLs, historial del terminal o registros
compartidos. Los archivos de GUI nativa y RPC no pueden combinarse. Nunca
expongas públicamente la capacidad de firmar o automatizar; al terminar, detén
con la misma lista completa de archivos.

## Diagnóstico y actualización

### Actualizar conservando las carteras

1. Haz una copia cifrada y comprueba la recuperación antes de actualizar.
2. Obtén la versión revisada que vas a usar. Compara el nuevo `.env.example`
   con tu `.env` sin sobrescribir secretos; revisa versiones, hashes e imágenes.
   Inspecciona Compose resuelto localmente y oculta secretos antes de compartirlo.
3. Termina las operaciones pendientes y detén la instalación con
   `docker compose stop`, usando su lista completa de archivos. Conserva `.env`,
   los datos de cartera y los volúmenes persistentes. Vuelve
   a compilar y recrear con exactamente el **mismo proyecto Compose y los mismos
   archivos de modalidad**. Para la modalidad predeterminada:

   ```bash
   docker compose --env-file .env config --images
   docker compose build --pull
   docker compose up -d
   ```

4. Abre la cartera, comprueba red y datos y vuelve a autenticarte si hace falta.

La actualización admitida v0.4 → v1.0 **no requiere convertir archivos de cartera**.
Se conservan las preferencias de plugins/Fusion y el marcador de propiedad;
no hay una versión intermedia. Los cambios de entorno se aplican al recrear.
Al pasar de la autenticación web en memoria hay que cargar el cliente nuevo
y acceder una vez: las sesiones que solo estaban en memoria no se pueden recuperar.
Nunca uses `down --volumes` para actualizar.

### Diagnóstico por síntomas

Empieza por `docker compose ps` y `docker compose logs`, con los mismos archivos
de modalidad de tu instalación. Comparte solo registros sin secretos, nunca
`.env`, semillas, archivos de cartera, bases de autenticación o credenciales.

| Síntoma | Primera comprobación y siguiente paso sin borrar datos |
|---|---|
| Contraseña rechazada o acceso denegado | Comprueba el nombre del host, la cookie, la caducidad y el escape de contraseña en `.env` (`$$`). Tras cambiar ajustes, recrea con `up -d` y accede de nuevo. Un 403 puede indicar un problema de origen, no una contraseña incorrecta. |
| La página no conecta | Revisa que los servicios estén listos y el puerto HTTP elegido. Cambia los puertos del acceso web si hay conflicto; no publiques noVNC directamente. |
| Mensaje de sesión terminada o escritorio vacío | Si terminó la última ventana o asistente, usa `up -d` y deja abierta la pestaña. Si no, revisa los registros de cartera por fallos o errores de inicio; no borres datos. |
| Tor está listo, pero la cartera no conecta | Revisa sus registros y la conexión con la red y servidores externos. Un SOCKS local listo no prueba acceso a Internet. Nunca compartas semillas para diagnosticarlo. |
| Cartera vacía o red equivocada | Comprueba `NETWORK` y variables heredadas de la shell; selecciona la red correcta y recrea antes de plantearte restaurar. Cada red tiene datos separados. |
| Falla la copia o restauración | Comprueba volumen, red, modalidad, ruta del archivo y solicitudes de contraseña. Conserva cualquier registro y volumen de recuperación pendiente; atiende al resultado de la recuperación, no borres volúmenes. |
| No aparece la ventana nativa | En Linux comprueba `DISPLAY`, Xauthority y X11/XWayland local. En macOS revisa Docker Desktop, XQuartz y la salida del script; consulta la referencia de plataformas, sin recurrir a `xhost +` ni desactivar seccomp. |
| Fallan la distribución o los atajos del teclado | Activa el campo, utiliza teclas adicionales o entrada virtual de noVNC, o elige la modalidad nativa; consulta [teclado del navegador](#teclado-del-navegador). |
| Valor inválido de idioma, tema, Fusion o red | Corrige `.env` y recrea. El inicio rechaza valores inválidos en lugar de elegir otros sin avisar. |

### Restablecer solo la autenticación web

Este paso avanzado sirve cuando has identificado un problema en el almacenamiento
de sesiones. Si está corrupto, no se puede leer o escribir o su formato no es
compatible, la autenticación deniega el acceso en lugar de sustituirlo o pasar
a memoria. Los datos de cartera son independientes. Consulta
[Seguridad](../SECURITY.md#web-access-and-recovery-controls).

En una shell POSIX con Python 3 en el host, averigua e inspecciona el volumen
**exacto** de autenticación de esta instalación. Detén y elimina sus contenedores
sin borrar volúmenes:

```bash
AUTH_VOLUME="$(docker compose config --format json | python3 -c 'import json,sys; print(json.load(sys.stdin)["volumes"]["auth-session-data"]["name"])')"
docker compose down
docker volume inspect "$AUTH_VOLUME"
```

Comprueba que el nombre inspeccionado corresponde exclusivamente a la
autenticación de esta instalación. Solo entonces elimina ese volumen y recrea:

```bash
docker volume rm "$AUTH_VOLUME"
docker compose up -d
```

Las sesiones antiguas necesitarán un nuevo acceso. No elimines volúmenes de
cartera/Tor ni uses `down --volumes`. No incluyas bases de autenticación en
registros ni paquetes compartidos.

## Probar sin fondos

Explora el escritorio del navegador con una copia del código separada y
desechable y una cartera Chipnet nueva, sin fondos. Nunca importes una cartera
real, semilla o claves privadas; no envíes fondos ni publiques una dirección
para recibirlos.

1. Sigue los [requisitos](#elegir-la-instalación). **Antes de compilar o iniciar**,
   crea `.env` solo si no existe en la copia desechable y define una
   `BASIC_AUTH_PASSWORD` exclusiva (`$$` para `$` literal), `NETWORK=chipnet`,
   `ECD_WALLET_VOLUME=ecd-v1-demo-wallet` y `ECD_TOR_VOLUME=ecd-v1-demo-tor`.
   Conserva `MODE=novnc`, `USE_TOR=true`, `CASHFUSION_AUTO_FUSE=false`,
   `WALLET_AUTO_CREATE=false` y `JSONRPC_ENABLED=false`. Usa solo el archivo
   Compose base, sin los de modalidad nativa/RPC.
2. Conserva `CADDY_EDGE_BIND=127.0.0.1` y `CADDY_SITE_ADDRESS=localhost`. Elige
   puertos libres, por ejemplo `CADDY_HTTP_HOST_PORT=18080` y
   `CADDY_HTTPS_HOST_PORT=18443`. Asigna a las cinco imágenes etiquetas locales
   libres y exclusivas del ensayo mediante `ELECTRON_CASH_IMAGE`, `TOR_IMAGE`,
   `AUTH_SESSION_IMAGE`, `CADDY_IMAGE` y `FAIL2BAN_IMAGE`.
3. Comprueba que el proyecto `ecd-v1-demo`, los dos nombres explícitos de
   volúmenes, todos los volúmenes con prefijo del proyecto, etiquetas de imágenes
   y puertos están libres; cambia nombres y puertos si están ocupados. Usa una
   shell sin ajustes heredados de Compose o ejecución: sus variables prevalecen
   sobre `.env`. Inspecciona el modelo resuelto localmente (contiene la contraseña;
   no lo compartas). Confirma Chipnet, puertos locales y solo recursos desechables:

```bash
docker compose --env-file .env -f docker-compose.yml -p ecd-v1-demo config
docker compose --env-file .env -f docker-compose.yml -p ecd-v1-demo build --pull
docker compose --env-file .env -f docker-compose.yml -p ecd-v1-demo up -d
```

Abre `http://127.0.0.1:18080/` (ajusta el puerto si elegiste otro), accede y
crea la cartera Chipnet nueva de forma interactiva. Prueba teclado, idioma,
tema y cierre y reapertura de la aplicación. Para reiniciar o recrear, repite
el mismo comando `up -d` con el alcance explícito anterior. Mantén semillas y
contraseñas privadas. Los servicios externos de prueba pueden no estar disponibles;
ver ajustes de CashFusion no demuestra una fusión en Chipnet y **este ensayo
no debe iniciar ninguna ronda**.

Detén con `docker compose --env-file .env -f docker-compose.yml -p ecd-v1-demo down`.
Solo cuando hayas confirmado que **todos los volúmenes resueltos pertenecen
exclusivamente a este ensayo desechable**, repite el comando con `--volumes`
para borrar sus datos. Mantén el mismo `.env`, archivo Compose y proyecto.
Nunca apliques esta limpieza a recursos de carteras reales ni uses Docker prune global.

## Opciones técnicas y límites

Consulta esta sección cuando necesites precisar un ajuste o el funcionamiento
de las sesiones. Para el uso habitual bastan los ajustes del inicio rápido.

### Teclado del navegador

noVNC transmite el texto normal y las teclas de edición, pero el navegador o
el sistema pueden interceptar atajos para cambiar de aplicación o ir a la
barra de direcciones. Utiliza sus botones de teclas adicionales para Ctrl/Alt
y Ctrl-Alt-Delete. Al cambiar de ventana comprueba el campo activo y libera
los modificadores que hayan quedado pulsados tras perder el foco.

El botón de teclado solicita el teclado en pantalla del dispositivo o navegador
mediante un campo de texto oculto. No es un panel de teclas para hacer clic;
en un navegador de escritorio puede no aparecer ningún teclado. El texto llega
al campo remoto; las teclas especiales se envían desde la barra. La distribución,
las teclas muertas y los métodos de entrada (IME) varían. Prueba la entrada virtual
o una ventana nativa admitida si tu distribución no funciona bien. Nunca pegues
una semilla en el portapapeles. Un teclado virtual no protege frente a capturas
ni todos los registradores de pulsaciones. El alcance se limita a combinaciones
de navegador y dispositivo probadas, no a todos los IME; estos controles no
corresponden a las modalidades nativa o headless.

### Redes y ciclo de vida

`NETWORK=mainnet` es el valor predeterminado para BCH real. Electron Cash 4.4.6
admite exactamente `mainnet`, `testnet`, `testnet4`, `scalenet`, `chipnet` y
`regtest`; un valor vacío o desconocido impide arrancar. Define `NETWORK` en
`.env` y recrea. Para seleccionarla temporalmente, solo en Bash:

```bash
NETWORK=chipnet docker compose up -d
```

Repite la selección al operar después, o guárdala en `.env` para evitar volver
por accidente a mainnet. Mainnet usa la raíz del volumen; las otras redes tienen
subdirectorios separados para carteras, configuración y plugins externos.
Los archivos adicionales de Compose eligen funciones, no redes. Elimina los
antiguos `CHIPNET=true` y `TESTNET4=true`; no cambies red, rutas de cartera ni
idioma mediante `ELECTRONCASH_ARGS` (usa `EC_LANGUAGE` para configuraciones nuevas
y Preferencias de Electron Cash para configuraciones existentes).
Los servidores de prueba pueden no estar disponibles. Regtest necesita un
servidor Electrum compatible y accesible; la instalación no incluye un nodo BCH completo.

### Referencia de sesiones web

- `BASIC_AUTH_PASSWORD` no puede estar vacía, superar 256 caracteres, contener
  saltos de línea, retornos de carro o NUL, ni empezar por `CHANGE_ME`.
  Son límites de aceptación, no una comprobación de robustez de la contraseña.
- La cookie temporal no tiene Max-Age/Expires; su sesión de servidor caduca
  30 minutos después del acceso. La recordada tiene Max-Age y un plazo de
  servidor de 30 días. Ni la actividad ni las consultas pasivas renuevan el plazo.
- La aplicación no guarda la contraseña web en localStorage, sessionStorage
  ni URLs. Utiliza una cookie HTTP HttpOnly, SameSite=Strict y Secure bajo HTTPS.
  Se permite el autocompletado del gestor de contraseñas; esto no significa que
  el navegador no conserve credenciales o rastros de uso.
- Las sesiones sobreviven a reinicios, recreaciones y down/up solo si se
  conservan la cookie, el volumen de autenticación y el plazo original.
  Recrear con la misma contraseña las mantiene. Cambiarla y recrear las revoca;
  volver a la antigua no recupera las sesiones anteriores.
- Visitar `/` revoca una sesión temporal; una recordada válida redirige al
  escritorio. Un POST del mismo origen a `/auth/logout` revoca cualquiera de
  las dos. Las consultas de estado de otras pestañas no cierran tu acceso.
  Los errores de red, 5xx y 403 no prueban caducidad; un 401 explícito devuelve
  al formulario.
- Eliminar carteras, hacer copias o restaurarlas no copia ni restablece las
  sesiones web. El servidor guarda el hash de cada token opaco de sesión,
  no el token reutilizable. Los detalles de SQLite, generaciones
  de credenciales y límites ante intrusiones están en
  [Seguridad](../SECURITY.md#web-access-and-recovery-controls).

### Procedencia de los plugins

`plugins.json` recoge fuentes, versiones, hashes SHA-256 de fuente/ZIP y
activación. La compilación rechaza hashes que no coincidan y el inicio vuelve
a verificar los archivos incluidos. No hay un catálogo abierto ni descargas
de plugins durante la ejecución. Para cambiar uno, revisa el código, actualiza
expresamente versiones y hashes y vuelve a compilar. La coincidencia del hash
identifica los archivos declarados; no demuestra que cualquier plugin sea seguro.

### Controles de CashFusion

Estos valores iniciales solo se aplican a preferencias de cartera ausentes:

| Variable | Valor predeterminado / significado |
|---|---|
| `CASHFUSION_FUSION_MODE` | `custom` |
| `CASHFUSION_FUSE_DEPTH` | `3` rondas; `0` significa ilimitadas en Electron Cash |
| `CASHFUSION_SELF_FUSE_PLAYERS` | `1`, sin fusión consigo misma |
| `CASHFUSION_SELECTOR_MODE` | `count`; alternativas `size`, `fraction` |
| `CASHFUSION_SELECTOR_COUNT` | `10` monedas como objetivo |
| `CASHFUSION_SELECTOR_SIZE_BCH` | `0.0001` BCH para selección por tamaño |
| `CASHFUSION_SELECTOR_FRACTION` | `1.0`, intervalo 0.0–1.0, para selección por fracción |
| `CASHFUSION_QUEUED_AUTOFUSE` | `4` |
| `CASHFUSION_AUTOFUSE_CONFIRMED_ONLY` | `true` |

El perfil inicial usa modo `custom`, un participante de la misma cartera por
ronda (sin fusión consigo misma) y participación automática solo cuando todas
las monedas de la cartera están confirmadas. Los ajustes de cola y selección
no activan la fusión automática mientras `CASHFUSION_AUTO_FUSE=false`.
Los modos admitidos son `normal`, `consolidate`, `fan-out` y `custom`; la profundidad
es de 0–10, los participantes de 1–2, la cantidad de 10–9999 y la cola de 1–10.
El tamaño debe ser al menos 0.0001 BCH, con un máximo de ocho decimales; la
fracción debe estar entre 0.0 y 1.0. Usa el punto decimal en `.env`, también
cuando la interfaz esté en español.

Los controles independientes de la instalación se aplican a fusiones manuales
y automáticas:

- `CASHFUSION_FEE_BUDGET=0` no añade límite de comisión. Un entero positivo
  limita la contribución atribuible de comisión minera de la cartera de origen
  por ronda, en satoshis, comprobada en la transacción final antes de firmar.
  No es un presupuesto acumulado de gasto.
- `CASHFUSION_MIN_UTXO=1000` excluye entradas menores de 1.000 satoshis;
  la igualdad se admite si se cumplen los demás requisitos. Cero no añade
  umbral. Si una entrada es demasiado pequeña, se excluye el grupo nativo
  completo de su dirección, conservando la vinculación y las exclusiones de
  monedas congeladas, tokens y confirmaciones.
- Un límite positivo rechaza entradas de procedencia no atribuible o mezclada
  y varios participantes de la misma cartera cuando no puede acotarse con
  seguridad su contribución. Cada objeto de fusión conserva los límites;
  los reintentos comprueban de nuevo la transacción final, sin una base de
  gastos compartida. Las preferencias guardadas no pueden desactivarlos.
- Ambos valores deben ser enteros entre 0 y 2.100.000.000.000.000. Un valor
  vacío, negativo, fraccionario, mal formado o mayor impide arrancar. Recrea
  tras editar `.env`. Son controles de la instalación vinculados por hash a
  Electron Cash 4.4.6, no preferencias de la aplicación original.
  `CASHFUSION_TARGET` no se admite; utiliza los selectores count/size/fraction.

### Imágenes, almacenamiento y límites de seguridad

[`.env.example`](../.env.example) es la referencia de configuración. Fija
Electron Cash, noVNC, Tor y Caddy con identificadores y hashes de
fuente. `ELECTRON_CASH_IMAGE`, `TOR_IMAGE`, `AUTH_SESSION_IMAGE`, `CADDY_IMAGE`
y `FAIL2BAN_IMAGE` permiten nombrar los resultados locales de compilación;
los servicios de acceso web usan etiquetas locales v1.0 por defecto. Vuelve
a compilar en lugar de sustituirlas por imágenes remotas sin verificar.

Los procesos de cartera se ejecutan con UID/GID 10001:10001. El inicio rechaza
permisos de propiedad o enlaces simbólicos inseguros en lugar de reparar
contenidos desconocidos sin avisar; los datos de cartera se guardan en
`/home/electroncash/.electron-cash`. Las sesiones web utilizan el volumen
independiente `auth-session-data` del proyecto, montado solo en auth-session
en `/auth-data/` (base `/auth-data/sessions.sqlite`). La notificación de cierre
no requiere socket Docker, acceso a los PID del host ni capacidades adicionales.
La consulta pasiva de recuperación tiene un tiempo máximo de 3 segundos por
petición, intervalo de 5 segundos tras terminar y espera progresiva limitada a
30 segundos durante una interrupción; los servicios web disponen de hasta seis
segundos para avisar a la página abierta antes de detenerse.

Sistemas de archivos raíz de solo lectura, almacenamiento temporal y recursos limitados,
capacidades restringidas, procesos de cartera sin root, sesiones/TLS/fail2ban
y copias cifradas aportan varias capas de protección, **no una auditoría ni una
garantía absoluta**. Un equipo comprometido o un administrador de Docker puede
leer los datos de cartera. Sigue abierto el aviso **CVE-2024-23342** de `ecdsa`:
las operaciones privadas requieren el componente nativo BCH secp256k1
verificado; no se afirma que la vulnerabilidad original esté corregida.

Consulta [Seguridad](../SECURITY.md) y [validación de plataformas](platform-validation.md)
para los límites detallados y el alcance observado. Los comandos y evidencias
de validación de mantenimiento están en [la sección de validación del README](../README.md#validation);
las comprobaciones sintéticas no certifican todos los equipos macOS, modelos
de hardware, arquitecturas o instalaciones públicas.
