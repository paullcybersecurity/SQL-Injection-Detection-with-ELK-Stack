# SQL-Injection-Detection-with-ELK-Stack

# Objective

The objective of this lab is to deploy a ```deliberately vulnerable web application (DVWA),``` execute a SQL injection attack chain against it, and build a SIEM detection and alert rule to catch the activity — demonstrating web-layer attack detection as a contrast to the network/auth-layer detection built for the SSH brute-force lab.

# Environment
 | Role    | Host name     |   Tool stack
 | :---:      | :---:      | :---:
 | Attacker  | Paull-attacker-kali | Kali linux, broswer.
 | Victim | paull-analyst | Ubuntu server, Apache, MariaDB, PHP, DVWA,Filebeat.
 | Siem | paull - sensor | Ubuntu server, ElasticSearch, kibana 
  * Note - All three VMs run in VMware Workstation on an isolated internal network. Private IP ranges shown in screenshots are lab-only and in-accessible by external entity.
    
# Setup summary

  **1.** LAMP stack installed on the victim host: ``` sudo apt install apache2 mariadb-server php php-mysqli php-gd libapache2-mod-php -y ```
   
  **2.** DVWA database created: ``` CREATE DATABASE dvwa;CREATE USER 'dvwa'@'localhost' IDENTIFIED BY 'dvwapass123';GRANT ALL PRIVILEGES ON dvwa.* TO 'dvwa'@'localhost';FLUSH PRIVILEGES; ```

 

    
   **3.** DVWA cloned and configured:
   ```
   cd /var/www/html sudo git clone https://github.com/digininja/DVWA.git dvwa
   sudo chown -R www-data:www-data /var/www/html/dvwa
   sudo chmod -R 755 /var/www/html/dvwa
```
    
   ***3(a) Database credentials set in config/config.inc.php to match the created database. allow_url_include enabled in php.ini to satisfy DVWA's setup requirements.***
  
  **4.** Database initialized via ```setup.php``` > "Create / Reset Database", then logged in with default credentials ```(admin / password).```

  **5.** Security level set to Low (DVWA Security page) — required to make the SQL injection vulnerability reliably exploitable without DVWA's built-in input sanitization interfering.

**6.** Filebeat extended to ship Apache logs, adding a second ```filestream``` input alongside the existing SSH/syslog input:
   
```yaml
filebeat.inputs:
 type: filestream
  id: system-logs
  enabled: true
  paths:
  - /var/log/auth.log
  - /var/log/syslog```
type: filestream
  id: apache-logs
  enabled: true
  paths:
    - /var/log/apache2/access.log
    - /var/log/apache2/error.log.
```
  
# Attack Simulation:

**Target:** DVWA's SQL Injection module ```(/dvwa/vulnerabilities/sqli/)``` **Method:** manual payload injection via the **"User ID"** input field, escalating from authentication bypass to full data exfiltration.

