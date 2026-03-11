# NetGhost

> Herramienta de escaneo, diagnóstico y detección de conflictos para redes corporativas Windows.  
> Construida íntegramente en PowerShell con interfaz gráfica WPF nativa. Sin dependencias externas, sin instalación.

---

## Índice

- [¿Qué es NetGhost?](#qué-es-netghost)
- [Motivación](#motivación)
- [Características principales](#características-principales)
- [Capturas de pantalla](#capturas-de-pantalla)
- [Requisitos](#requisitos)
- [Instalación y uso](#instalación-y-uso)
- [Descripción funcional detallada](#descripción-funcional-detallada)
  - [Autodetección de red](#autodetección-de-red)
  - [Escaneo de red](#escaneo-de-red)
  - [Análisis de conflictos](#análisis-de-conflictos)
  - [Herramientas ARP](#herramientas-arp)
  - [Log de actividad](#log-de-actividad)
- [Arquitectura técnica](#arquitectura-técnica)
- [Estructura del código](#estructura-del-código)
- [Limitaciones conocidas](#limitaciones-conocidas)
- [Hoja de ruta](#hoja-de-ruta)
- [Contribuir](#contribuir)
- [Licencia](#licencia)

---

## ¿Qué es NetGhost?

NetGhost es una herramienta de administración de red desarrollada en PowerShell que permite a técnicos e ingenieros de sistemas realizar un inventario rápido de los equipos activos en una subred local, detectar conflictos de direccionamiento IP y diagnosticar problemas de acceso, todo desde una interfaz gráfica WPF sin necesidad de instalar ningún software adicional.

El nombre hace referencia a esa clase de problemas de red que no se ven a simple vista: equipos fantasma que responden a ping pero no aparecen en el ARP, IPs duplicadas que causan intermitencias, o nombres NetBIOS repetidos que generan confusión en entornos de dominio. NetGhost los saca a la luz.

---

## Motivación

En entornos corporativos medianos y grandes es habitual encontrarse con situaciones que los monitores de red convencionales no detectan bien: una impresora con IP fija que colisiona con el DHCP, un equipo que fue retirado pero cuya entrada ARP sigue activa, o dos máquinas que comparten nombre NetBIOS tras una migración mal documentada.

Las herramientas profesionales de gestión de red (SolarWinds, PRTG, Lansweeper) cubren estos casos pero requieren infraestructura, licencias y tiempo de despliegue. En muchos escenarios lo que se necesita es algo que funcione ahora mismo, en el equipo que tienes delante, sin instalar nada.

NetGhost nació de esa necesidad concreta: un script que cualquier técnico pueda ejecutar directamente en PowerShell, que tenga una interfaz usable (no solo texto en consola) y que dé información accionable en menos de un minuto.

---

## Características principales

**Escaneo de red activo**
- Ping concurrente sobre el rango de IPs configurado, con timeout ajustable.
- Resolución de nombre NetBIOS vía `nbtstat` con fallback a DNS inverso.
- Lectura de tabla ARP para obtener direcciones MAC sin elevar privilegios.
- Identificación del fabricante por prefijo OUI (tabla integrada, sin llamadas externas).
- Comprobación de puertos SMB (445) y RDP (3389) por TCP para evaluar accesibilidad.
- Clasificación automática de cada host: `OK`, `WARN` o `SIN_ARP`.

**Autodetección de red**
- Identifica el adaptador de red activo con gateway definido al arrancar.
- Filtra adaptadores virtuales: Hyper-V, VMware, VirtualBox, TAP, Tunnel, WAN Miniport, Bluetooth y otros.
- Priorización por métrica de ruta, que es el mismo criterio que usa Windows para elegir la interfaz preferida.
- Precarga automática de subred y rango en los campos de configuración.

**Análisis de conflictos**
- Detección de IPs duplicadas: misma IP con distintas MACs en la tabla ARP.
- Detección de nombres NetBIOS duplicados: mismo nombre en diferentes IPs.
- Identificación de hosts con acceso bloqueado: responden ping pero tienen SMB y RDP cerrados.
- Catalogación de entradas ARP huérfanas: host visible pero sin registro ARP.
- Clasificación por severidad: `CRITICO` (riesgo de colisión activo) o `AVISO` (anomalía que requiere revisión).

**Herramientas ARP**
- Volcado de la tabla ARP completa del sistema.
- Limpieza de caché ARP local con confirmación previa (requiere privilegios de administrador).

**Log de actividad**
- Registro persistente durante la sesión de todas las operaciones realizadas.
- Niveles: INFO, OK, WARN, ERROR.
- Exportación a fichero `.txt`.

**Exportación de datos**
- Resultados de conflictos exportables a CSV con fecha y hora en el nombre del fichero.
- Log de actividad exportable a texto plano.

**Interfaz**
- WPF nativa, tema oscuro, sin dependencias de terceros.
- Escaneo no bloqueante mediante Runspace independiente con comunicación por cola thread-safe.
- Barra de progreso en tiempo real con contador de hosts descubiertos.
- Coloración de filas por estado directamente desde el evento `LoadingRow` del DataGrid.

---

## Capturas de pantalla

> _Las capturas se añadirán en próximas versiones del repositorio._

---

## Requisitos

| Requisito | Detalle |
|---|---|
| Sistema operativo | Windows 10 / Windows 11 / Windows Server 2016 o superior |
| PowerShell | 5.1 o superior (incluido en Windows por defecto) |
| .NET Framework | 4.5 o superior (incluido en Windows 10+) |
| Módulo NetTCPIP | Incluido por defecto desde Windows 8 / Server 2012 |
| Privilegios | Usuario estándar para escaneo. Administrador para limpiar caché ARP |
| Conectividad | El equipo debe estar en la misma subred o tener enrutamiento hacia el rango escaneado |

No requiere instalación, módulos de PowerShell adicionales, ni acceso a internet.

---

## Instalación y uso

### Descarga directa

```
git clone https://github.com/tuusuario/netghost.git
cd netghost
```

O descarga el fichero `NetGhost.ps1` directamente desde la sección _Releases_.

### Ejecución

**Opción 1 — Desde el explorador de Windows**

Clic derecho sobre `NetGhost.ps1` → _Ejecutar con PowerShell_.

Si Windows bloquea la ejecución por política, usar la opción 2.

**Opción 2 — Desde PowerShell con bypass puntual**

```powershell
powershell -ExecutionPolicy Bypass -File .\NetGhost.ps1
```

Este parámetro aplica únicamente a la ejecución actual, no modifica la política del sistema.

**Opción 3 — Desde PowerShell ISE o VS Code**

Abrir el fichero y pulsar F5, o ejecutar en terminal integrado:

```powershell
. .\NetGhost.ps1
```

### Flujo de trabajo típico

1. Al arrancar, NetGhost detecta automáticamente la red activa y precarga los campos de subred y rango.
2. Revisar los valores detectados. Ajustar el rango si solo se quiere escanear un segmento concreto.
3. Pulsar **▶ ESCANEAR**. El escaneo corre en segundo plano y los resultados aparecen en tiempo real.
4. Una vez finalizado, ir a **⚡ Conflictos** y pulsar **ANALIZAR CONFLICTOS**.
5. Revisar los conflictos detectados. Exportar a CSV si se necesita documentar o escalar.
6. Usar **Herramientas ARP** si se necesita limpiar la caché o ver la tabla completa.
7. El **Log de actividad** recoge todo lo ocurrido durante la sesión y puede exportarse.

---

## Descripción funcional detallada

### Autodetección de red

Al iniciar, NetGhost llama a `Get-ActiveSubnet`, que usa `Get-NetIPConfiguration` para obtener los adaptadores de red disponibles. El proceso de selección tiene dos fases:

**Fase 1 — Filtrado por calidad del adaptador**

Se descartan adaptadores que cumplan cualquiera de estas condiciones:
- Sin gateway IPv4 definido (no son la puerta de salida a la red).
- Estado distinto de `Up`.
- Descripción que coincida con el patrón: `Hyper-V`, `VMware`, `VirtualBox`, `Loopback`, `Teredo`, `isatap`, `Bluetooth`, `TAP`, `Tunnel`, `WAN Miniport`, `Microsoft Wi-Fi Direct`, `Kernel Debug`.

Si no queda ningún candidato tras el filtro estricto, se aplica un filtro de fallback menos restrictivo que solo exige que el adaptador esté activo y tenga IP asignada.

**Fase 2 — Selección por métrica de ruta**

Entre los candidatos válidos se selecciona el que tenga menor suma de `RouteMetric + InterfaceMetric`. Esta es exactamente la misma lógica que usa Windows para decidir qué interfaz usa por defecto para enrutar tráfico. En equipos con Ethernet y Wi-Fi simultáneamente activos, seleccionará la correcta en la gran mayoría de casos.

**Resultado**

El objeto devuelto contiene: subred base (tres primeros octetos), rango calculado según el prefijo de máscara, IP local, prefijo CIDR, alias de la interfaz y gateway. Todo se muestra en el banner informativo de la página de escaneo y se vuelca al log.

El botón **⬡ DETECTAR RED** permite repetir el proceso en cualquier momento sin reiniciar la aplicación, útil cuando el equipo cambia de red entre sesiones.

---

### Escaneo de red

El escaneo se ejecuta en un Runspace independiente del hilo de la UI para no bloquearla. La comunicación entre el Runspace y la interfaz gráfica se realiza mediante una `ConcurrentQueue<PSObject>`, que es thread-safe por diseño.

**Proceso por cada IP del rango:**

1. **Ping** — Se envía un ICMP echo request con timeout de 500 ms usando `System.Net.NetworkInformation.Ping`. Solo se continúa si la respuesta es `Success`.

2. **Lookup ARP** — Se consulta la tabla ARP que se leyó al inicio del escaneo (una sola lectura para todo el rango). Si la IP tiene entrada, se obtiene su MAC. Si no, se marca como `N/A`.

3. **Identificación de fabricante** — Se toman los 3 primeros bytes de la MAC (OUI) y se buscan en una tabla integrada de 20 fabricantes habituales en entornos corporativos. Sin consultas externas ni APIs.

4. **Resolución de nombre** — Se intenta primero con `nbtstat -A` buscando registros `<00> UNIQUE` (nombre de máquina NetBIOS). Si falla, se usa `[System.Net.Dns]::GetHostEntry` para resolución DNS inversa. Si ambos fallan, se devuelve `?`.

5. **Comprobación de puertos** — Se abre una conexión TCP asíncrona a los puertos 445 (SMB) y 3389 (RDP) con timeout de 600 ms. Se registra si el puerto está abierto o cerrado.

6. **Clasificación del host:**
   - `OK` — Tiene MAC en ARP y al menos uno de los dos puertos accesible.
   - `WARN` — Tiene MAC pero ninguno de los dos puertos responde.
   - `SIN_ARP` — Responde ping pero no tiene entrada en la tabla ARP.

**Actualización de la UI:**

Un `DispatcherTimer` con intervalo de 250 ms drena la cola de resultados en el hilo de la UI y los añade al `ObservableCollection` que está enlazado al DataGrid. El DataGrid se actualiza automáticamente por binding. La barra de progreso y los contadores se actualizan en el mismo tick.

---

### Análisis de conflictos

El análisis opera sobre los datos ya recogidos en el escaneo más una lectura fresca de la tabla ARP del sistema. Se ejecuta de forma síncrona ya que es rápido por naturaleza.

**Tipo 1 — IP Duplicada (CRITICO)**

Se lee la tabla ARP completa y se agrupa por IP. Si una misma IP aparece asociada a más de una MAC distinta, es un conflicto de direccionamiento activo. Esto suele indicar que dos equipos tienen la misma IP estática, o que un equipo ha cambiado de tarjeta de red sin actualizar la reserva DHCP. Es la situación más grave porque causa pérdidas de paquetes intermitentes difíciles de diagnosticar.

**Tipo 2 — NetBIOS Duplicado (CRITICO)**

Se recorren los resultados del escaneo y se agrupan los nombres NetBIOS. Si el mismo nombre aparece en más de una IP, hay una colisión de nombres en la red. En entornos de dominio esto puede impedir que el equipo se autentique correctamente o que los recursos compartidos sean accesibles.

**Tipo 3 — Acceso Bloqueado (AVISO)**

Hosts que responden ping pero tienen los puertos 445 y 3389 cerrados. Puede ser un firewall mal configurado, un equipo con perfil de red en modo público, o un dispositivo no Windows (impresora, NAS, switch gestionado) que no expone esos servicios. Requiere revisión pero no implica un conflicto activo.

**Tipo 4 — Sin entrada ARP (AVISO)**

Hosts que responden ping pero no tienen registro en la tabla ARP local. Puede ocurrir cuando el equipo está en una subred diferente enrutada, cuando el ARP está siendo suprimido por algún agente de seguridad, o cuando la entrada ha expirado entre el ping y la lectura ARP. Merece investigación porque puede esconder un equipo no autorizado.

---

### Herramientas ARP

**Ver tabla ARP**

Ejecuta `arp -a` y vuelca la salida completa en el área de texto de la página de herramientas. Útil para inspección manual rápida sin salir de la aplicación.

**Limpiar caché ARP**

Ejecuta `netsh interface ip delete arpcache` tras confirmación del usuario. Esta operación requiere que PowerShell esté ejecutándose con privilegios de administrador. Útil cuando se ha resuelto un conflicto de IP y se quiere forzar al sistema a redescubrir las MACs correctas sin esperar a que expire el TTL de las entradas ARP (por defecto 2 minutos en Windows).

---

### Log de actividad

Cada operación relevante queda registrada con timestamp y nivel:

- `[·]` INFO — Operaciones normales de inicio, navegación, configuración.
- `[✔]` OK — Operaciones completadas con éxito.
- `[⚠]` WARN — Situaciones que requieren atención pero no son errores.
- `[✘]` ERROR — Fallos en operaciones.

El log es de solo lectura durante la sesión. Puede limpiarse manualmente o exportarse a `.txt` desde la barra de herramientas de la página de log.

---

## Arquitectura técnica

```
NetGhost.ps1
│
├── [Hilo UI – STA Dispatcher]
│   ├── WPF Window (XAML embebido en here-string)
│   ├── ObservableCollection → DataGrid binding
│   ├── DispatcherTimer (250ms) → drena ConcurrentQueue
│   └── Eventos de botones, navegación, exportación
│
└── [Runspace independiente – STA]
    ├── Ping range (secuencial, timeout 500ms)
    ├── ARP lookup (tabla leída una vez al inicio)
    ├── NetBIOS/DNS resolution
    ├── TCP port check 445, 3389 (async, timeout 600ms)
    └── Enqueue resultados → ConcurrentQueue<PSObject>
```

**Por qué un Runspace y no Start-Job o Start-ThreadJob**

`Start-Job` serializa los objetos al cruzar el límite del proceso, lo que elimina los tipos .NET que necesitamos. `Start-ThreadJob` no está disponible en PowerShell 5.1 sin instalar el módulo `ThreadJob`. El Runspace con `BeginInvoke` es la solución nativa que funciona en todas las versiones requeridas y permite compartir referencias a objetos .NET directamente, incluyendo la `ConcurrentQueue`.

**Por qué ConcurrentQueue y no un Synchronized ArrayList**

`ConcurrentQueue<T>` está diseñada específicamente para el patrón productor-consumidor. El Runspace produce, el DispatcherTimer consume. No requiere locks explícitos y `TryDequeue` es una operación atómica que no bloquea. Un `ArrayList` sincronizado requeriría un lock en cada acceso y añadiría complejidad innecesaria.

**Por qué XAML embebido en lugar de fichero externo**

Para mantener el script como fichero único y autocontenido. `XamlReader.Load()` parsea el XAML en tiempo de ejecución. Esta aproximación tiene la limitación de que `DataTemplate.Triggers` no está soportado por el parser parcial de PowerShell (a diferencia del compilador XAML de Visual Studio), por lo que la lógica de coloración de filas se delega al evento `LoadingRow` del DataGrid.

---

## Estructura del código

El script está dividido en bloques numerados y comentados:

```
BLOQUE 0  – Configuración global y variables compartidas
BLOQUE 1  – Función Get-ActiveSubnet (autodetección de red)
BLOQUE 2  – Funciones de escaneo: Get-ArpTable, Get-MACVendor, Start-NetworkScan
BLOQUE 3  – Funciones de análisis: Find-Conflicts, Clear-ArpCache
BLOQUE 4  – Definición XAML de la interfaz WPF
BLOQUE 4b – Carga de la ventana y referencias a controles
BLOQUE 4c – Funciones de UI: Write-Log, Set-ActivePage, Set-ScanningState, Invoke-DetectNetwork
BLOQUE 4d – Eventos de navegación del sidebar
BLOQUE 4e – Eventos de detección y escaneo
BLOQUE 4f – Eventos de análisis de conflictos
BLOQUE 4g – Eventos de herramientas ARP
BLOQUE 4h – Eventos de log
BLOQUE 4i – Inicialización y arranque
```

---

## Limitaciones conocidas

**Resolución NetBIOS**

`nbtstat -A` puede tardar entre 1 y 3 segundos por host en redes con latencia o cuando el servicio NetBIOS sobre TCP/IP está deshabilitado. En redes con muchos hosts esto alarga el tiempo de escaneo. Una mejora futura pasaría por paralelizar las resoluciones de nombre.

**Tabla OUI de fabricantes**

La tabla integrada cubre los prefijos más comunes en entornos corporativos pero no es exhaustiva. No hay consulta al registro público de la IEEE. Para entornos con hardware menos habitual muchos fabricantes aparecerán como `Desconocido`.

**Rango máximo de 254 hosts**

El rango de escaneo está limitado a subredes /24 o menores (máximo 254 hosts por rango). En subredes /16 o mayores el campo `HASTA` se limita automáticamente a 254. Si se necesita cubrir rangos mayores hay que ejecutar múltiples escaneos cambiando la subred base.

**Detección de conflictos basada en ARP local**

El análisis de IPs duplicadas se basa en la tabla ARP del equipo donde corre NetGhost, no en una captura de tráfico. Esto significa que solo detecta conflictos que han generado entradas ARP en ese equipo concreto. Un conflicto entre dos hosts que nunca han comunicado con el equipo de análisis no será visible.

**Requiere misma subred o enrutamiento**

El ping y las comprobaciones TCP deben poder alcanzar los hosts objetivo. En redes con VLANs sin enrutamiento entre ellas solo se verán los hosts de la VLAN local.

**Sin persistencia entre sesiones**

Los resultados del escaneo y los conflictos detectados no se guardan al cerrar la aplicación, salvo que se exporten manualmente a CSV o txt antes de cerrar.

---

## Contribuir

Las contribuciones son bienvenidas.
---

## Licencia

Este proyecto se distribuye bajo licencia MIT. Consulta el fichero `LICENSE` para más detalles.

---

*NetGhost — Porque los problemas de red que no se ven son los que más duelen.*
