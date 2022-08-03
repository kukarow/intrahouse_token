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
Добавим наш скрипт в планировщик задачь cron и будем выполнять задачу  в фоновом режиме от имени супер пользователя (root).

Откроем текстовым редактором nano, системный файл crontab(планировщик задач):
```
sudo nano /etc/crontab
```
Результат вывода будет приблизительно похож на :
```
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# Example of job definition:
# .---------------- minute (0 - 59)
# |  .------------- hour (0 - 23)
# |  |  .---------- day of month (1 - 31)
# |  |  |  .------- month (1 - 12) OR jan,feb,mar,apr ...
# |  |  |  |  .---- day of week (0 - 6) (Sunday=0 or 7) OR sun,mon,tue,wed,thu,fri,sat
# |  |  |  |  |
# *  *  *  *  * user-name command to be executed
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#
```
Добавим в планировщик задач наш скрипт , и будем его запускать от имени root, кажен час (как пример).
/home/pi/script.sh - прямой путь к файлу.
```
*  1  *  *  *   root    /home/pi/script.sh
```
Сохраним внесенные изменения : жмакаем CTRL+X далее Y далее ENTR. (роскладка* должна быть EN).  

Добавим в планировщик задач еще пользователей, чтоб скрипт запускался от имени пользователя (не рута)

Просмотрим списки пользователей(нас интересует пользователь pi , так как по пути к исполнительному файлу , видно что такова учетная запись должна быть, провери ) :
```
getent passwd
```
или
```
cat /etc/passwd
```
Результат примерно следующий -
```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-timesync:x:100:101:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
systemd-network:x:101:103:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
_apt:x:103:65534::/nonexistent:/usr/sbin/nologin
pi:x:1000:1000:,,,:/home/pi:/bin/bash
messagebus:x:104:110::/nonexistent:/usr/sbin/nologin
_rpc:x:105:65534::/run/rpcbind:/usr/sbin/nologin
statd:x:106:65534::/var/lib/nfs:/usr/sbin/nologin
sshd:x:107:65534::/run/sshd:/usr/sbin/nologin
avahi:x:108:113:Avahi mDNS daemon,,,:/run/avahi-daemon:/usr/sbin/nologin
lightdm:x:109:114:Light Display Manager:/var/lib/lightdm:/bin/false
rtkit:x:110:116:RealtimeKit,,,:/proc:/usr/sbin/nologin
pulse:x:111:119:PulseAudio daemon,,,:/run/pulse:/usr/sbin/nologin
saned:x:112:122::/var/lib/saned:/usr/sbin/nologin
colord:x:113:123:colord colour management daemon,,,:/var/lib/colord:/usr/sbin/nologin
hplip:x:114:7:HPLIP system user,,,:/run/hplip:/bin/false
systemd-coredump:x:996:996:systemd Core Dumper:/:/usr/sbin/nologin
```
Для минимизации выедания глаз и приданию более читабельного вида пропишем :
```
getent passwd | awk -F: '{ print $1}'
```
Находим пользователя pi (он нас в данный момент интересует), и проверим его активность :
```
lastlog
```

Вывод примерно следующий 
```
Username         Port     From             Latest
root                                       **Never logged in**
daemon                                     **Never logged in**
bin                                        **Never logged in**
sys                                        **Never logged in**
sync                                       **Never logged in**
games                                      **Never logged in**
man                                        **Never logged in**
lp                                         **Never logged in**
mail                                       **Never logged in**
news                                       **Never logged in**
uucp                                       **Never logged in**
proxy                                      **Never logged in**
www-data                                   **Never logged in**
backup                                     **Never logged in**
list                                       **Never logged in**
irc                                        **Never logged in**
gnats                                      **Never logged in**
nobody                                     **Never logged in**
systemd-timesync                           **Never logged in**
systemd-network                            **Never logged in**
systemd-resolve                            **Never logged in**
_apt                                       **Never logged in**
pi               pts/1    192.168.0.103    Wed Aug  3 20:16:49 +0100 2022
messagebus                                 **Never logged in**
_rpc                                       **Never logged in**
statd                                      **Never logged in**
sshd                                       **Never logged in**
avahi                                      **Never logged in**
lightdm                                    **Never logged in**
rtkit                                      **Never logged in**
pulse                                      **Never logged in**
saned                                      **Never logged in**
colord                                     **Never logged in**
hplip                                      **Never logged in**
systemd-coredump  
```
даллее 
```
 last -a
```
Результат:
```
pi       pts/1        Wed Aug  3 20:16   still logged in    192.168.0.103
pi       pts/1        Wed Aug  3 18:47 - 20:16  (01:29)     192.168.0.103
pi       pts/0        Wed Aug  3 18:32   still logged in    192.168.0.103
pi       tty7         Wed Aug  3 18:32   still logged in    :0
pi       tty1         Wed Aug  3 18:29    gone - no logout
reboot   system boot  Thu Jan  1 01:00   still running      5.15.32-v7+
pi       tty7         Wed Aug  3 18:28 - crash (-19207+17:2 :0
pi       tty1         Wed Aug  3 18:28 - crash (-19207+17:2
reboot   system boot  Thu Jan  1 01:00   still running      5.15.32-v7+

```
Списки пользователей проверены , интересующий нас кандедат найден , активность кандедата подтверждена .

Давайте добавим в crontab (планировщик задач) выполнение нашего скрипта от имени пользователя pi .

Все как  и ранее было описано , открываем системный файл crontab редактором nano от имени root:
```
sudo nano /etc/crontab
```
И добавляем задачу :
```
*  1  *  *  *   pi    /home/pi/script.sh
```
### Ознакомительная часть
- [X] [Crontab](https://www.youtube.com/watch?v=zwvqVppij8E&ab_channel=ADV-IT)
- [X] [Использование CRON и команды crontab](http://www.codenet.ru/webmast/php/cron.php)
- [X] [Как добавить задание в планировщик Cron в Linux/UNIX](https://blog.sedicomm.com/2017/07/24/kak-dobavit-zadanie-v-planirovshhik-cron-v-linux-unix/)
- [X] [Как вывести список пользователей в Linux](https://zalinux.ru/?p=5578)
