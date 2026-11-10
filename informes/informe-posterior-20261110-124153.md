# Informe posterior a la aplicación de hardening: SW1

Fecha: 2026-11-10 12:41:53
Equipo: SW1 (10.7.30.3)

| ID | Sección | Regla | Antes | Después | Observación |
|---|---|---|---|---|---|
| R01 | Management Plane | Cifrado de contraseñas | No cumple | Cumple |  |
| R02 | Management Plane | enable secret robusto, sin enable password | Cumple | Cumple |  |
| R03 | Management Plane | Banners de advertencia (login y exec) | No cumple | Cumple |  |
| R04 | Management Plane | SSH v2, time-out de 60 s y 3 reintentos | No cumple | No cumple |  |
| R05 | Management Plane | VTY: solo SSH, inactividad de 5 min y ACL de gestión | Cumple | Cumple |  |
| R06 | Management Plane | Consola con tiempo de inactividad de 5 min | Cumple | Cumple |  |
| R07 | Management Plane | Servidor HTTP/HTTPS apagado | No cumple | Cumple |  |
| R08 | Management Plane | Registro con marca de tiempo y buffer | Cumple | Cumple |  |
| R09 | Control Plane | Servicios innecesarios apagados (pad, source-route, bootp, CDP) | No cumple | Cumple |  |
| R10 | Complementaria | Puertos sin uso apagados | Cumple | Cumple |  |

Cumplimiento antes: 5/10
Cumplimiento después: 9/10
