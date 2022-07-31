# intrahouse_token


Заходим под рутом на малинку.
Для получени информации о плате малинки:
```
cat /proc/cpuinfo
```
Результатом будет:
```
<processor	: 0
model name	: ARMv7 Processor rev 4 (v7l)
BogoMIPS	: 38.40
Features	: half thumb fastmult vfp edsp neon vfpv3 tls vfpv4 idiva idivt vfpd32 lpae evtstrm crc32 
CPU implementer	: 0x41
CPU architecture: 7
CPU variant	: 0x0
CPU part	: 0xd03
CPU revision	: 4

processor	: 1
model name	: ARMv7 Processor rev 4 (v7l)
BogoMIPS	: 38.40
Features	: half thumb fastmult vfp edsp neon vfpv3 tls vfpv4 idiva idivt vfpd32 lpae evtstrm crc32 
CPU implementer	: 0x41
CPU architecture: 7
CPU variant	: 0x0
CPU part	: 0xd03
CPU revision	: 4

processor	: 2
model name	: ARMv7 Processor rev 4 (v7l)
BogoMIPS	: 38.40
Features	: half thumb fastmult vfp edsp neon vfpv3 tls vfpv4 idiva idivt vfpd32 lpae evtstrm crc32 
CPU implementer	: 0x41
CPU architecture: 7
CPU variant	: 0x0
CPU part	: 0xd03
CPU revision	: 4

processor	: 3
model name	: ARMv7 Processor rev 4 (v7l)
BogoMIPS	: 38.40
Features	: half thumb fastmult vfp edsp neon vfpv3 tls vfpv4 idiva idivt vfpd32 lpae evtstrm crc32 
CPU implementer	: 0x41
CPU architecture: 7
CPU variant	: 0x0
CPU part	: 0xd03
CPU revision	: 4

Hardware	: BCM2835
Revision	: a020d3
Serial		: 00000000de0b314f
Model		: Raspberry Pi 3 Model B Plus Rev 1.3>
```
Для привязки к железу малинки, нас интересуют следующие параметры:
```
Hardware	: BCM2835
Revision	: a020d3
Serial		: 00000000de0b314f
Model		: Raspberry Pi 3 Model B Plus Rev 1.3
```
Данные поля мы поместим в наш скрипт.

Создадим наш скрипт, который будет проверять на совпадение параметры малинки:
```
nano script.sh
```
Добавим в наш script.sh информацию о нашей малинке которую узнали ранее -поля-  Hardware,Revision,Serial,Model 
Данные поля являются уникальными  для каждой малинки.(от них и будем плясать ).

Примертный вид script.sh:

```
!/bin/bash

#Параметры платы малинки которые мы ранее узнали и добавили сюда.

Hardware_token=BCM2835
Revision_token=a020d3
Serial_token=00000000de0b314f
#Model_token=Raspberry Pi 3 Model B Plus Rev 1.3

#запрос новых данных(информации) о плате малинки.
Current_serial=$(cat /proc/cpuinfo)

if [[ "$Current_serial" == *"$Serial_token"* ]]; then #Сравнение старых данных с новыми.
     echo "ok"
     mkdir terasoft                                   #Если данные  совпадают то все ок, и мы просто создадим папку terasoft.
else
     echo "ne ok"
     rmdir terasoft                                   #Если данные не совпадают то мы удалим папку
fi


```

Дадим нашему скрипту права на исполнение (устанавливаем флаг на исполнение).
```
chmod ugo+x script.sh
```
Запустим наш скрипт для теста:
```
./script.sh
```
