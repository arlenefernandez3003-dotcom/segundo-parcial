wget https://repo.zabbix.com/zabbix/7.0/ubuntu/pool/main/z/zabbix-release/zabbix-release_7.0-2+ubuntu24.04_all.deb
sudo dpkg -i zabbix-release_7.0-2+ubuntu24.04_all.deb
sudo apt update
sudo apt install zabbix-server-mysql zabbix-frontend-php zabbix-apache-conf zabbix-sql-scripts zabbix-agent snmp mariadb-server -y
sudo systemctl enable --now mariadb

sudo mysql -uroot -e "
  CREATE DATABASE zabbix CHARACTER SET utf8mb4 COLLATE utf8mb4_bin;
  CREATE USER 'zabbix'@'localhost' IDENTIFIED BY 'ZabbixPass123!';
  GRANT ALL PRIVILEGES ON zabbix.* TO 'zabbix'@'localhost';
  SET GLOBAL log_bin_trust_function_creators = 1;
  FLUSH PRIVILEGES;"

zcat /usr/share/zabbix-sql-scripts/mysql/server.sql.gz | mysql --default-character-set=utf8mb4 -uzabbix -pZabbixPass123! zabbix
sudo mysql -uroot -e "SET GLOBAL log_bin_trust_function_creators = 0;"

sudo sed -i 's/# DBPassword=/DBPassword=ZabbixPass123!/' /etc/zabbix/zabbix_server.conf
sudo systemctl restart zabbix-server zabbix-agent apache2
sudo systemctl enable zabbix-server zabbix-agent apache2
sudo systemctl status zabbix-server
