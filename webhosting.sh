#!/usr/bin/env bash

set -euo pipefail

clear

export PATH="$PATH:/root/.local/bin"

NGINX_CONF_CONFIG_SRC="/opt/webhosting/nginx/nginx.conf"
NGINX_OPTIM_CONFIG_SRC="/opt/webhosting/nginx/optim.conf"
NGINX_SHORTPIXEL_CONFIG_SRC="/opt/webhosting/nginx/shortpixel.conf"
NGINX_MAPPING_CONFIG_SRC="/opt/webhosting/nginx/mapping.conf"
NGINX_CACHE_CONFIG_SRC="/opt/webhosting/nginx/cache.conf"
NGINX_SECURITY_CONFIG_SRC="/opt/webhosting/nginx/security.conf"
OPCACHE_CONFIG_URL="/opt/webhosting/php/opcache.ini"
NGINX_BAD_UA_LIST_SRC="/opt/nginx-ultimate-bad-bot-blocker/_generator_lists/bad-user-agents.list"
NGINX_BAD_IP_LIST_SRC="/opt/nginx-ultimate-bad-bot-blocker/_generator_lists/bad-ip-addresses.list"
NGINX_FAKE_GOOGLE_BOT_SRC="/opt/nginx-ultimate-bad-bot-blocker/_generator_lists/fake-googlebots.list"
NGINX_BAD_REFERRER_LIST_SRC="/opt/nginx-ultimate-bad-bot-blocker/_generator_lists/bad-referrers.list"

#################################
########### FUNCTIONS ###########
#################################
function title() {
  echo ""
  echo "=============================="
  echo "=== $1"
  echo "=============================="
  echo ""
}
function subtitle() {
  echo "# $1"
}
function checkreturncode() {
  if [ $1 -ne 0 ]; then
    echo "  --> $2 failed with exit code $1"
    exit 1
  else
    echo "  --> $2 successfully completed"
  fi
}
function systemcheck() {
  if [ "$EUID" -ne 0 ]; then
    echo "❌ This script must be run as root"
    exit 1
  fi
}
function generateletsencryptcert() {
  subtitle "Generating Let's Encrypt certificate for $DOMAIN_NAME"
  LE_DOMAINS="-d $DOMAIN_NAME"
  /root/.local/bin/certbot certonly --webroot -w /var/www/letsencrypt $LE_DOMAINS --agree-tos --email postmaster@$DOMAIN_NAME --non-interactive --quiet
  checkreturncode $? "Let's Encrypt certificate generation"
}
function nginxcheck() {
  if nginx -t; then
    systemctl restart nginx > /dev/null
  else
    echo "❌ Nginx syntax error, please check the configuration!"
    nginx -t
    exit 1
  fi
}
function createdatabase() {
  subtitle "Generating database & user for WordPress"
  WP_DB_NAME=$(echo "$DOMAIN_NAME" | tr -d '.-' )
  WP_DB_USER=$(echo "$DOMAIN_NAME" | tr -d '.-' )
  WP_DB_PASS=$(pwgen --capitalize --numerals -1 22)
  cat > /root/wordpress_init.sql <<EOF
CREATE DATABASE IF NOT EXISTS \`$WP_DB_NAME\` DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS '$WP_DB_USER'@'localhost' IDENTIFIED BY '$WP_DB_PASS';
GRANT ALL PRIVILEGES ON \`$WP_DB_NAME\`.* TO '$WP_DB_USER'@'localhost';
FLUSH PRIVILEGES;
EOF
  mariadb < /root/wordpress_init.sql
  checkreturncode $? "WordPress database and user creation"
}
function askforargs() {
  if [[ -n "$PHP_VERSION_ARG" ]]; then
    PHP_VERSION="$PHP_VERSION_ARG"
  else
    echo "Please pass the PHP version as an argument --php <version>"
    exit 1
  fi

  if [[ -n "$DOMAIN_NAME_ARG" ]]; then
    DOMAIN_NAME="$DOMAIN_NAME_ARG"
  else
    echo "Please pass the domain name as an argument --domain <domain>"
    exit 1
  fi
}
function installphp() {
  subtitle "Configuring repository for Ondřej Surý PPA"
  if ! grep -Rq "ondrej/php" /etc/apt/sources.list*; then
    add-apt-repository -y ppa:ondrej/php
    apt-get update
  fi
  subtitle "Installing PHP $PHP_VERSION and extensions"
  apt-get -yq install \
    php$PHP_VERSION \
    php$PHP_VERSION-cli \
    php$PHP_VERSION-fpm \
    php$PHP_VERSION-common \
    php$PHP_VERSION-curl \
    php$PHP_VERSION-mbstring \
    php$PHP_VERSION-opcache \
    php$PHP_VERSION-xml \
    php$PHP_VERSION-zip \
    php$PHP_VERSION-mysql \
    php$PHP_VERSION-gd \
    php$PHP_VERSION-imagick \
    php$PHP_VERSION-intl \
    php$PHP_VERSION-bcmath \
    php$PHP_VERSION-redis \
    php$PHP_VERSION-memcached \
    php$PHP_VERSION-imap \
    php$PHP_VERSION-exif \
    php$PHP_VERSION-ftp \
    php$PHP_VERSION-soap \
    php$PHP_VERSION-pspell \
    php$PHP_VERSION-xmlrpc \
    php$PHP_VERSION-gmp \
    php$PHP_VERSION-apcu
  checkreturncode $? "PHP $PHP_VERSION and extensions installation"

  subtitle "Optimizing PHP $PHP_VERSION configuration"
  ln -sf "$OPCACHE_CONFIG_URL" /etc/php/$PHP_VERSION/fpm/conf.d/99-opcache-custom.ini
  sed -i 's/^memory_limit = .*/memory_limit = 1024M/' /etc/php/$PHP_VERSION/cli/php.ini
  sed -i 's|^;*date.timezone =.*|date.timezone = Europe/Paris|' /etc/php/$PHP_VERSION/cli/php.ini
  sed -i 's|^;*date.timezone =.*|date.timezone = Europe/Paris|' /etc/php/$PHP_VERSION/fpm/php.ini
  systemctl reload php$PHP_VERSION-fpm || systemctl restart php$PHP_VERSION-fpm
  checkreturncode $? "PHP $PHP_VERSION configuration optimization"
}
function fpmuseradd() {
  subtitle "Generating system user for FPM process"
  SYSTEM_USER=$(echo "$DOMAIN_NAME" | tr -d '.-' )
  mkdir -p /var/www/${DOMAIN_NAME}
  if ! id "$SYSTEM_USER" &>/dev/null; then
    useradd --shell /bin/bash -d /var/www/${DOMAIN_NAME} -g www-data -G www-data "$SYSTEM_USER"
    checkreturncode $? "User $SYSTEM_USER creation"
    mkdir -p /var/cache/nginx/${DOMAIN_NAME}
    chown -R ${SYSTEM_USER}:www-data /var/cache/nginx/${DOMAIN_NAME}
  else
    echo "  --> User $SYSTEM_USER already exists, skipping creation"
  fi
}
function createwpcron() {
  CRON_CMD="*/5 * * * * wp --path=/var/www/${DOMAIN_NAME} cron event run --due-now"
  if grep -q "cron event run" /var/spool/cron/crontabs/"$SYSTEM_USER" 2>/dev/null; then
    echo "  --> WordPress cron job already exists for user $SYSTEM_USER, skipping creation"
  else
    echo "  --> Creating WordPress cron job for user $SYSTEM_USER"
    (crontab -u "$SYSTEM_USER" -l 2>/dev/null || true; echo "$CRON_CMD") | crontab -u "$SYSTEM_USER" -
  fi
}

function nginxhttpvhost() {
  subtitle "Setting up Nginx vhost for $DOMAIN_NAME"
  NGINX_HTTP_CONFIG_URL="https://gist.githubusercontent.com/bilyboy785/7965e619604846e96a284b6a5f962242/raw/69369286be12f80b6dfb9630cfb66ba7edb17171/nginx.http.conf"
  TMP_NGINX_HTTP_CONF="/tmp/nginx.http.conf"
  curl -fsSL "$NGINX_HTTP_CONFIG_URL" -o "$TMP_NGINX_HTTP_CONF"
  export DOMAIN_NAME 
  envsubst '$DOMAIN_NAME' < "$TMP_NGINX_HTTP_CONF" > /etc/nginx/conf.d/${DOMAIN_NAME}.conf
  rm -f "$TMP_NGINX_HTTP_CONF"
  checkreturncode $? "Nginx vhost for $DOMAIN_NAME setup"
}

function nginxhttpsvhost() {
  subtitle "Finalizing Nginx vhost configuration for WordPress SSL with caching"
  NGINX_HTTPS_CONFIG_URL="https://raw.githubusercontent.com/bilyboy785/webhosting/refs/heads/main/nginx/https.conf"
  TMP_NGINX_HTTPS_CONF="/tmp/nginx.https.conf"
  curl -fsSL "$NGINX_HTTPS_CONFIG_URL" -o "$TMP_NGINX_HTTPS_CONF"
  export DOMAIN_NAME SYSTEM_USER
  envsubst '$DOMAIN_NAME $SYSTEM_USER' < "$TMP_NGINX_HTTPS_CONF" > /etc/nginx/conf.d/${DOMAIN_NAME}.conf
  rm -f "$TMP_NGINX_HTTPS_CONF"
  nginxcheck
  checkreturncode $? "Nginx vhost for WordPress SSL with caching setup"
}

function deployfpmpool() {
  subtitle "Configuring PHP-FPM pool for $DOMAIN_NAME"
  PHPFPM_POOL_CONFIG_URL="https://raw.githubusercontent.com/bilyboy785/webhosting/refs/heads/main/php/pool.conf"
  TMP_PHPFPM_POOL_CONF="/tmp/phpfpm.pool.conf"
  curl -fsSL "$PHPFPM_POOL_CONFIG_URL" -o "$TMP_PHPFPM_POOL_CONF"
  export DOMAIN_NAME SYSTEM_USER
  envsubst '$DOMAIN_NAME $SYSTEM_USER' < "$TMP_PHPFPM_POOL_CONF" > /etc/php/$PHP_VERSION/fpm/pool.d/${DOMAIN_NAME}.conf
  rm -f "$TMP_PHPFPM_POOL_CONF"
  rm -f /etc/php/$PHP_VERSION/fpm/pool.d/www.conf
  systemctl restart php$PHP_VERSION-fpm
  checkreturncode $? "PHP-FPM pool for $DOMAIN_NAME configuration"
}

function resume() {
  subtitle "Summary"
  PHP_VERSION=$(php --version | head -1 | cut -d\( -f1)
  BORG_VERSION=$(borg --version | cut -d\  -f2)
  BORGMATIC_VERSION=$(borgmatic --version | cut -d\  -f2)
  CERTBOT_VERSION=$(certbot --version | awk '{print $2}')
  BPYTOP_VERSION=$(bpytop --version | awk '{print $2}')
  MARIADB_VERSION=$(mariadb --version | awk '{print $5}' | tr -d ,)
  NGINX_VERSION=$(nginx -v 2>&1 | awk -F/ '{print $2}')
  echo "PHP Version       : $PHP_VERSION"
  echo "MariaDB Version   : $MARIADB_VERSION"
  echo "Nginx Version     : $NGINX_VERSION"
  echo "Borg Version      : $BORG_VERSION"
  echo "Borgmatic Version : $BORGMATIC_VERSION"
  echo "Certbot Version   : $CERTBOT_VERSION"
  echo "Bpytop Version    : $BPYTOP_VERSION"
  echo "Database Credentials : $WP_DB_NAME - $WP_DB_USER - $WP_DB_PASS"
  echo "FTP Credentials      : $DOMAIN_NAME - $SYSTEM_USER - $FTP_PASS - Port 21"
  echo "FTP_USER=$SYSTEM_USER" >> /etc/environment
  echo "FTP_PASS=$FTP_PASS" >> /etc/environment
  echo "FTP_HOST=$DOMAIN_NAME" >> /etc/environment
  echo "DB_NAME=$WP_DB_NAME" >> /etc/environment
  echo "DB_USER=$WP_DB_USER" >> /etc/environment
  echo "DB_PASS=$WP_DB_PASS" >> /etc/environment
}

function updateconfig() {
  subtitle "Updating config repositories"
  cd /opt/nginx-ultimate-bad-bot-blocker && git pull origin master
  cd /opt/webhosting && git pull
  cd /root
  subtitle "Updating bad user agents list"
  cat "$NGINX_BAD_UA_LIST_SRC" | sed 's/^/~*/g' | sed 's/$/\ 1;/g' > /etc/nginx/bots/bad-user-agents.conf
  subtitle "Updating bad ips list"
  cat "$NGINX_BAD_IP_LIST_SRC" | sed 's/$/\ 1;/g' > /etc/nginx/bots/bad-ip-list.conf
  subtitle "Updating fake google bots list"
  cat "$NGINX_FAKE_GOOGLE_BOT_SRC" | sed 's/$/\ 1;/g' > /etc/nginx/bots/fake-googlebots.conf
  subtitle "Updating bad referrers list"
  cat "$NGINX_BAD_REFERRER_LIST_SRC" | sed 's/^/~*/g' | sed 's/$/\ 1;/g' > /etc/nginx/bots/bad-referrers.conf
  if nginx -t; then
    systemctl reload nginx
  else
    echo "❌ Nginx syntax error after configuration update, please check the configuration!"
    nginx -t
    exit 1
  fi
  subtitle "Updating PHP configuration files from repository"
  for dir in /etc/php/*/fpm/conf.d /etc/php/*/cli/conf.d; do
    PHP_VER=$(echo "$dir" | cut -d'/' -f4)
    ln -sf "$OPCACHE_CONFIG_URL" "/etc/php/$PHP_VER/mods-available/opcache-custom.ini"
    systemctl reload php$PHP_VER-fpm || systemctl restart php$PHP_VER-fpm
  done
  exit 0
}

PHP_VERSION_ARG=""
DOMAIN_NAME_ARG=""
if [[ $# -eq 0 ]]; then
  echo "No arguments provided. Proceeding with interactive mode."
  echo "Usage : $0 [--php <version>] [--domain <domain>]"
  exit 0
fi
while [[ $# -gt 0 ]]; do
  case $1 in
    --php)
      PHP_VERSION_ARG="$2"
      shift 2
      ;;
    --domain)
      DOMAIN_NAME_ARG="$2"
      shift 2
      ;;
    --update)
      updateconfig
      ;;
    *)
      shift
      ;;
  esac
done

systemcheck

if [[ -f /opt/initialized.flag ]]; then
  echo "⚠️ Server already initialized"
  askforargs
  installphp
  fpmuseradd
  createwpcron
  deployfpmpool
  nginxhttpvhost
  generateletsencryptcert
  nginxhttpsvhost
  createdatabase
  resume
  exit 0
fi

askforargs

subtitle "Cloning webhosting repository"
if [[ ! -d /opt/webhosting ]]; then
  git clone https://github.com/bilyboy785/webhosting /opt/webhosting --depth 1
  checkreturncode $? "Webhosting repository cloning"
fi

subtitle "Cloning nginx-ultimate-bad-bot-blocker repository"
if [[ ! -d /opt/nginx-ultimate-bad-bot-blocker ]]; then
  git clone https://github.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker.git /opt/nginx-ultimate-bad-bot-blocker --depth 1
  checkreturncode $? "nginx-ultimate-bad-bot-blocker repository cloning"
fi

fpmuseradd

createwpcron

subtitle "Initialize directories"
mkdir -p /etc/borgmatic
mkdir -p /var/backups/borg
mkdir -p /var/log/borgmatic
mkdir -p /var/log/php
mkdir -p /etc/nginx/snippets
mkdir -p /var/www/letsencrypt
mkdir -p /etc/nginx/ssl/
mkdir -p /etc/nginx/bots
checkreturncode $? "Directories creation"

subtitle "Updating repositories & installing base packages"

apt-get update -qq
apt-get -yq upgrade
apt-get -yq install ca-certificates \
  lsb-release \
  apt-transport-https \
  software-properties-common \
  build-essential \
  gcc \
  git \
  zsh \
  curl \
  htop \
  ufw \
  unzip \
  wget \
  sshpass \
  fail2ban \
  python3 \
  python3-venv \
  python3-dev \
  redis-server \
  python3-pip \
  libssl-dev \
  libacl1-dev \
  liblz4-dev \
  libzstd-dev \
  libxxhash-dev \
  pkg-config \
  build-essential \
  libbrotli1 \
  imagemagick \
  libbrotli-dev \
  ca-certificates \
  gnupg \
  yq \
  lsb-release \
  software-properties-common \
  pipx
checkreturncode $? "Base packages installation"

subtitle "Docker installation"
install -m 0755 -d /etc/apt/keyrings
if [[ ! -f /etc/apt/keyrings/docker.gpg ]]; then
  subtitle "Keyring setup"
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
  chmod a+r /etc/apt/keyrings/docker.gpg
fi
if [[ ! -f /etc/apt/sources.list.d/docker.list ]]; then
  subtitle "Repo source setup"
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" > /etc/apt/sources.list.d/docker.list
  apt-get update -qq
  apt-get -yq install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
  checkreturncode $? "Docker installation"
  systemctl enable docker >/dev/null 2>&1
  systemctl start docker >/dev/null 2>&1
  checkreturncode $? "Docker service start"
fi

subtitle "Initializing pipx environment"
pipx ensurepath
echo "\$PATH=\$PATH:/root/.local/bin" >> /etc/environment
echo "DOMAIN_NAME=$DOMAIN_NAME" >> /etc/environment
checkreturncode $? "Adding domain name to environment vars"

pipx install pwgen

subtitle "Installing Oh My Zsh"
if [[ ! -d "/root/.oh-my-zsh" ]]; then
  export RUNZSH=no
  export CHSH=no
  sh -c "$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)" -- --unattended
  echo 'export PATH=$PATH:~/.local/bin' >> /root/.zshrc
fi
if [ "$SHELL" != "/usr/bin/zsh" ]; then
  chsh -s /usr/bin/zsh root
fi

installphp

deployfpmpool

subtitle "Installing Nginx from official repository"
if [ ! -f "/etc/apt/keyrings/nginx-archive-keyring.gpg" ]; then
  curl -fsSL https://nginx.org/keys/nginx_signing.key | gpg --dearmor | tee "/etc/apt/keyrings/nginx-archive-keyring.gpg"
fi

# if ! grep -q "nginx.org" /etc/apt/sources.list.d/nginx.list 2>/dev/null; then
#   DISTRO_CODENAME=$(lsb_release -cs)
#   echo "deb [signed-by=/etc/apt/keyrings/nginx-archive-keyring.gpg] http://nginx.org/packages/mainline/ubuntu $DISTRO_CODENAME nginx" > /etc/apt/sources.list.d/nginx.list
#   apt-get update
# fi

apt-get -yq install nginx-extras libnginx-mod-http-brotli-filter libnginx-mod-http-brotli-static
if ! systemctl is-active --quiet nginx; then
  systemctl enable nginx
  systemctl start nginx
fi
checkreturncode $? "Nginx installation"

subtitle "Nginx Configuration"
rm -f /etc/nginx/conf.d/default.conf
rm -f /etc/nginx/sites-available/default
rm -f /etc/nginx/sites-enabled/default

ln -sf "$NGINX_CONF_CONFIG_SRC" /etc/nginx/nginx.conf
checkreturncode $? "Nginx base config"

ln -sf "$NGINX_OPTIM_CONFIG_SRC" /etc/nginx/conf.d/optim.conf
checkreturncode $? "Nginx optimization configuration optimization"

ln -sf "$NGINX_MAPPING_CONFIG_SRC" /etc/nginx/conf.d/mapping.conf
checkreturncode $? "Nginx mapping configuration optimization"

ln -sf "$NGINX_CACHE_CONFIG_SRC" /etc/nginx/snippets/cache.conf
checkreturncode $? "Nginx cache configuration optimization"

ln -sf "$NGINX_SHORTPIXEL_CONFIG_SRC" /etc/nginx/snippets/shortpixel.conf
checkreturncode $? "Nginx ShortPixel configuration optimization"

ln -sf "$NGINX_SECURITY_CONFIG_SRC" /etc/nginx/snippets/security.conf
checkreturncode $? "Nginx security configuration optimization"

cat "$NGINX_BAD_UA_LIST_SRC" | sed 's/^/~*/g' | sed 's/$/\ 1;/g' > /etc/nginx/bots/bad-user-agents.conf
checkreturncode $? "Nginx bad UA configuration"

cat "$NGINX_BAD_IP_LIST_SRC" | sed 's/$/\ 1;/g' > /etc/nginx/bots/bad-ip-list.conf
checkreturncode $? "Nginx bad IP configuration"

cat "$NGINX_FAKE_GOOGLE_BOT_SRC" | sed 's/$/\ 1;/g' > /etc/nginx/bots/fake-googlebots.conf
checkreturncode $? "Nginx fake Google bots configuration"

cat "$NGINX_BAD_REFERRER_LIST_SRC" | sed 's/^/~*/g' | sed 's/$/\ 1;/g' > /etc/nginx/bots/bad-referrers.conf
checkreturncode $? "Nginx bad referrers configuration"

sed -i 's/^worker_processes .*/worker_processes auto;/' /etc/nginx/nginx.conf
sed -i 's/^worker_connections .*/worker_connections 4096;/' /etc/nginx/nginx.conf || true
if ! grep -q 'worker_connections' /etc/nginx/nginx.conf; then
  sed -i '/events {/a \    worker_connections 4096;' /etc/nginx/nginx.conf
fi
if systemctl is-active --quiet nginx; then
  systemctl reload nginx
fi

nginxcheck

subtitle "Configuring Nginx vhost for WordPress site"


nginxhttpvhost

subtitle "Generating strong dhparam for nginx SSL"
if [ ! -f /etc/nginx/ssl/dhparam.pem ]; then
  echo "openssl dhparam -out /etc/nginx/ssl/dhparam.pem 4096" | at now + 20 minutes
  checkreturncode $? "DHParam generation"
fi

nginxcheck

subtitle "Setting up WordPress cache directory and webroot"
chown -R ${SYSTEM_USER}:www-data /var/www/${DOMAIN_NAME}
chmod 755 /var/www/${DOMAIN_NAME}
if ! grep -q "/var/cache/nginx" /etc/fstab; then
  echo "tmpfs /var/cache/nginx tmpfs rw,size=512M,uid=$(id -u www-data),gid=$(id -g www-data),mode=0755 0 0" >> /etc/fstab
  checkreturncode $? "Fstab entry for WordPress cache directory"
fi
mkdir -p /var/cache/nginx/
chown www-data:www-data /var/www/letsencrypt
chmod 0755 /var/cache/nginx
systemctl daemon-reload
mountpoint -q /var/cache/nginx || mount /var/cache/nginx
mkdir -p /var/cache/nginx/${DOMAIN_NAME}
chown www-data:www-data /var/cache/nginx/${DOMAIN_NAME}
if systemctl is-active --quiet nginx; then
  systemctl reload nginx
fi
checkreturncode $? "WordPress cache directory and webroot setup"

subtitle "Installing and configuring MariaDB"
if  [[ ! -f /etc/apt/sources.list.d/mariadb.list ]]; then
  curl -fsSL https://mariadb.org/mariadb_release_signing_key.asc | gpg --dearmor -o /etc/apt/keyrings/mariadb-keyring.gpg
  UBUNTU_CODENAME=$(lsb_release -cs)
  echo "deb [signed-by=/etc/apt/keyrings/mariadb-keyring.gpg] https://mirror.mariadb.org/repo/10.11/ubuntu $UBUNTU_CODENAME main" > /etc/apt/sources.list.d/mariadb.list
  apt-get update
  apt-get -y install mariadb-server mariadb-client
  systemctl enable mariadb
  systemctl start mariadb
  checkreturncode $? "MariaDB installation"
fi

createdatabase

subtitle "Configuring UFW firewall"
ufw default deny incoming > /dev/null
ufw default allow outgoing > /dev/null
ufw allow 22/tcp > /dev/null
ufw allow 80/tcp > /dev/null
ufw allow 443/tcp > /dev/null
ufw allow 45876/tcp > /dev/null
ufw allow 21/tcp > /dev/null
ufw allow 21000:21010/tcp > /dev/null
ufw --force enable > /dev/null
checkreturncode $? "UFW firewall configuration"

subtitle "Installing backups tools: BorgBackup + Borgmatic"
pipx install borgbackup
pipx install borgmatic

if [[ ! -f /etc/borgmatic/config.yaml ]]; then
  subtitle "Generating Borgmatic configuration file"
  BORGMATIC_CONFIG_SRC="/opt/webhosting/borgmatic/config.yaml"
  export INSTANCE_HOSTNAME=$(hostname -f)
  envsubst '$INSTANCE_HOSTNAME' < "$BORGMATIC_CONFIG_SRC" > /etc/borgmatic/config.yaml
  checkreturncode $? "Borgmatic configuration file generation"
  if grep -q 'BORG_PASSPHRASE' /etc/environment; then
    PASSPHRASE=$(grep 'BORG_PASSPHRASE' /etc/environment | cut -d '=' -f2)
    yq -iy ".encryption_passphrase = \"$PASSPHRASE\"" /etc/borgmatic/config.yaml
    checkreturncode $? "Setting up borg passphrase for borgmatic config"
  else
    PASSPHRASE=$(pwgen -cn -1 64) && yq -iy ".encryption_passphrase = \"$PASSPHRASE\"" /etc/borgmatic/config.yaml
    echo "BORG_PASSPHRASE=$PASSPHRASE" >> /etc/environment
    checkreturncode $? "Adding passphrase to environment vars"
  fi
  borgmatic config validate
  checkreturncode $? "Borgmatic configuration validation"

  subtitle "Creating Borgmatic repository"
  borgmatic repo-create
  checkreturncode $? "Borgmatic repository creation"

  subtitle "Setting up Borgmatic daily backup cron job"
  CRON_CMD="0 2 * * * /root/.local/bin/borgmatic --log-file /var/log/borgmatic/backup.log"
  if grep -q 'borgmatic' /var/spool/cron/crontabs/root 2>/dev/null; then
    echo "  --> Borgmatic cron job already exists for user root, skipping creation"
  else
    (crontab -u "root" -l 2>/dev/null || true; echo "$CRON_CMD") | crontab -u "root" -
    checkreturncode $? "Borgmatic crontab setup"
  fi
fi

subtitle "Initial backup with Borgmatic"
borgmatic create --stats
checkreturncode $? "Initial backup with Borgmatic"

subtitle "Installing bpytop"
pipx install bpytop
checkreturncode $? "Bpytop installation"

subtitle "Installing Certbot and generating Let's Encrypt certificate"
pipx install certbot
pipx inject certbot certbot-dns-cloudflare
checkreturncode $? "Certbot installation"

subtitle "Configuring Fail2ban"
if [ -f /etc/fail2ban/jail.local ]; then
  rm -f /etc/fail2ban/jail.local > /dev/null 2>&1
fi
FAIL2BAN_JAIL_SRC="/opt/webhosting/fail2ban/jail.local"
ln -sf "$FAIL2BAN_JAIL_SRC" /etc/fail2ban/jail.local
if [ -f /etc/fail2ban/jail.conf ]; then
  rm -f /etc/fail2ban/jail.conf > /dev/null 2>&1
fi
FAIL2BAN_JAIL_SRC="/opt/webhosting/fail2ban/jail.conf"
ln -sf "$FAIL2BAN_JAIL_SRC" /etc/fail2ban/jail.conf
systemctl enable fail2ban
systemctl restart fail2ban
checkreturncode $? "Fail2ban configuration"

subtitle "Installing WP-CLI"
if [ ! -f /usr/local/bin/wp ]; then
  curl -s -o /usr/local/bin/wp https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar
  chmod +x /usr/local/bin/wp
  wp --info || { echo "❌ L'installation de WP-CLI a échoué"; exit 1; }
  checkreturncode $? "WP-CLI installation"
fi

generateletsencryptcert

nginxhttpsvhost

subtitle "Generating SSH key"
ssh-keygen -t rsa -b 4096 -f ~/.ssh/id_rsa -q -N ""

sed -i 's/# export PATH/export PATH/g' /root/.zshrc

CRON_CMD="0 4 * * * /bin/bash /opt/webhosting/webhosting.sh --update"
crontab -u "root" -l 2>/dev/null | grep -F -- "$CRON_CMD" >/dev/null 2>&1 || (
  (crontab -u "root" -l 2>/dev/null; echo "$CRON_CMD") | crontab -u "root" -
)
checkreturncode $? "Config update crontab setup"

subtitle "Start watchtower docker container for automatic docker image updates"
docker run -d --restart always --name watchtower -v /var/run/docker.sock:/var/run/docker.sock docker.io/martinbouillaud/watchtower:latest
checkreturncode $? "Watchtower docker container setup"

subtitle "Start docker FTP server"
FTP_PASS=$(pwgen --capitalize --numerals -1 22)
USER_PUID=$(id -u ${SYSTEM_USER})
docker run -d --restart always --name ftp -p 21:21 -p 21000-21010:21000-21010 -e USERS="${SYSTEM_USER}|${FTP_PASS}|/var/www/${DOMAIN_NAME}|${USER_PUID}" -e ADDDRESS="${DOMAIN_NAME}" -v /var/www/${DOMAIN_NAME}:/var/www/${DOMAIN_NAME} delfer/alpine-ftp-server
checkreturncode $? "FTP server docker container setup"

resume

echo "initialized" > /opt/initialized.flag