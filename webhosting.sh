#!/usr/bin/env bash

set -euo pipefail

clear

export PATH="$PATH:/root/.local/bin"

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

# function scriptexpandcertificate() {
#   cat > /root/.local/bin/expandssl <<EOF
# DOMAIN_NAME=$DOMAIN_NAME
# echo "Expanding Let's Encrypt certificate for $DOMAIN_NAME"
# read -rp "Enter additional domain aliases separated by spaces: " DOMAIN_ALIASES_ARRAY
# IFS=' ' read -r -a DOMAIN_ALIASES_ARRAY <<< "$DOMAIN_ALIASES"
# LE_DOMAINS="-d $DOMAIN_NAME"
# for alias in "${DOMAIN_ALIASES[@]}"; do
#   LE_DOMAINS+=" -d $alias"
# done
# /root/.local/bin/certbot certonly --webroot -w /var/www/letsencrypt $LE_DOMAINS --agree-tos --email postmaster@$DOMAIN_NAME --non-interactive --expand
# EOF
#   chmod +x /root/.local/bin/expandssl
# }

function systemcheck() {
  if [ "$EUID" -ne 0 ]; then
    echo "❌ This script must be run as root"
    exit 1
  fi
}

function generateletsencryptcert() {
  subtitle "Generating Let's Encrypt certificate for $DOMAIN_NAME"
  # Vérification de l'adresse IP du domaine principal
  SERVER_IP=$(curl -s https://api.ipify.org)
  DOMAIN_IPS=$(dig +short A "$DOMAIN_NAME" | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}')
  if ! echo "$DOMAIN_IPS" | grep -q "$SERVER_IP"; then
    echo "❌ Attention : $DOMAIN_NAME ne pointe pas vers l'IP du serveur ($SERVER_IP). Vérifiez la configuration DNS avant de continuer."
    read -rp "Appuyez sur Entrée pour continuer quand même, ou Ctrl+C pour annuler..."
  fi
  # Vérification pour chaque alias éventuel
  for alias in "${DOMAIN_ALIASES_ARRAY[@]}"; do
    [ -z "$alias" ] && continue
    ALIAS_IPS=$(dig +short A "$alias" | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}')
    if ! echo "$ALIAS_IPS" | grep -q "$SERVER_IP"; then
      echo "❌ Attention : $alias ne pointe pas vers l'IP du serveur ($SERVER_IP). Vérifiez la configuration DNS avant de continuer."
      read -rp "Appuyez sur Entrée pour continuer quand même, ou Ctrl+C pour annuler..."
    fi
  done
  LE_DOMAINS="-d $DOMAIN_NAME"
  for alias in "${DOMAIN_ALIASES_ARRAY[@]}"; do
    LE_DOMAINS+=" -d $alias"
  done
  /root/.local/bin/certbot certonly --webroot -w /var/www/letsencrypt $LE_DOMAINS --agree-tos --email postmaster@$DOMAIN_NAME --non-interactive --quiet
  checkreturncode $? "Let's Encrypt certificate generation"
}

function nginxcheck() {
  if nginx -t > /dev/null 2>&1; then
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

  # Génération du script SQL
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
    read -rp "Which PHP version will be used ? [7.4, 8.0, 8.2, 8.4, 8.5] (default: 8.4) : " PHP_VERSION
    PHP_VERSION=${PHP_VERSION:-8.4}
  fi

  if [[ -n "$DOMAIN_NAME_ARG" ]]; then
    DOMAIN_NAME="$DOMAIN_NAME_ARG"
  else
    read -rp "Primary domain name e.g., example.com): " DOMAIN_NAME
    DOMAIN_NAME=${DOMAIN_NAME:-example.com}
  fi
}

function installphp() {
  subtitle "Configuring repository for Ondřej Surý PPA"
  if ! grep -Rq "ondrej/php" /etc/apt/sources.list*; then
    add-apt-repository -y ppa:ondrej/php > /dev/null 2>&1
    apt-get update > /dev/null 2>&1
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
    php$PHP_VERSION-apcu > /dev/null 2>&1
  checkreturncode $? "PHP $PHP_VERSION and extensions installation"


  subtitle "Optimizing PHP $PHP_VERSION configuration"
  OPCACHE_CONFIG_URL="https://gist.githubusercontent.com/bilyboy785/7965e619604846e96a284b6a5f962242/raw/9bf89b53108745ef80f36a2cc3070bb527e4a658/opcache.ini"
  curl -fsSL "$OPCACHE_CONFIG_URL" -o "/etc/php/$PHP_VERSION/mods-available/opcache-custom.ini"
  ln -sf /etc/php/$PHP_VERSION/mods-available/opcache-custom.ini /etc/php/$PHP_VERSION/fpm/conf.d/99-opcache-custom.ini > /dev/null 2>&1
  sed -i 's/^memory_limit = .*/memory_limit = 1024M/' /etc/php/$PHP_VERSION/cli/php.ini > /dev/null 2>&1
  sed -i 's|^;*date.timezone =.*|date.timezone = Europe/Paris|' /etc/php/$PHP_VERSION/cli/php.ini > /dev/null 2>&1
  sed -i 's|^;*date.timezone =.*|date.timezone = Europe/Paris|' /etc/php/$PHP_VERSION/fpm/php.ini > /dev/null 2>&1
  systemctl reload php$PHP_VERSION-fpm || systemctl restart php$PHP_VERSION-fpm > /dev/null 2>&1
  checkreturncode $? "PHP $PHP_VERSION configuration optimization"
}

function fpmuseradd() {
  subtitle "Generating system user for FPM process"
  SYSTEM_USER=$(echo "$DOMAIN_NAME" | tr -d '.-' )
  mkdir -p /var/www/${DOMAIN_NAME} > /dev/null 2>&1
  cat > /var/www/${DOMAIN_NAME}/info.php <<EOF
<?php
phpinfo();
?>
EOF
  if ! id "$SYSTEM_USER" &>/dev/null; then
    useradd --shell /bin/bash -d /var/www/${DOMAIN_NAME} -g www-data -G www-data "$SYSTEM_USER" > /dev/null 2>&1
    checkreturncode $? "User $SYSTEM_USER creation"
    mkdir -p /var/cache/nginx/${DOMAIN_NAME} > /dev/null 2>&1
    chown -R ${SYSTEM_USER}:www-data /var/cache/nginx/${DOMAIN_NAME} > /dev/null 2>&1
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
  NGINX_HTTPS_CONFIG_URL="https://gist.githubusercontent.com/bilyboy785/7965e619604846e96a284b6a5f962242/raw/6d0309d133a4ae9925a458b2154c4d0492f68b80/nginx.https.conf"
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
  PHPFPM_POOL_CONFIG_URL="https://gist.githubusercontent.com/bilyboy785/7965e619604846e96a284b6a5f962242/raw/4d2dae4b40eec26070b79a6a53263b6b4f172727/fpm.pool.conf"
  TMP_PHPFPM_POOL_CONF="/tmp/phpfpm.pool.conf"
  curl -fsSL "$PHPFPM_POOL_CONFIG_URL" -o "$TMP_PHPFPM_POOL_CONF"
  export DOMAIN_NAME SYSTEM_USER
  envsubst '$DOMAIN_NAME $SYSTEM_USER' < "$TMP_PHPFPM_POOL_CONF" > /etc/php/$PHP_VERSION/fpm/pool.d/${DOMAIN_NAME}.conf
  rm -f "$TMP_PHPFPM_POOL_CONF"
  rm -f /etc/php/$PHP_VERSION/fpm/pool.d/www.conf > /dev/null 2>&1
  systemctl restart php$PHP_VERSION-fpm > /dev/null 2>&1
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
}

PHP_VERSION_ARG=""
DOMAIN_NAME_ARG=""
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
  deployfpmpool
  nginxhttpvhost
  generateletsencryptcert
  nginxhttpsvhost
  createdatabase
  resume
  exit 0
fi

askforargs

fpmuseradd

subtitle "Initialize directories"
mkdir -p /etc/borgmatic > /dev/null 2>&1
mkdir -p /var/backups/borg > /dev/null 2>&1
mkdir -p /var/log/borgmatic > /dev/null 2>&1
mkdir -p /var/log/php > /dev/null 2>&1
mkdir -p /etc/nginx/snippets > /dev/null 2>&1
mkdir -p /var/www/letsencrypt > /dev/null 2>&1
mkdir -p /etc/nginx/ssl/ > /dev/null 2>&1
checkreturncode $? "Directories creation"

subtitle "Updating repositories & installing base packages"

apt-get update -qq > /dev/null 2>&1
apt-get -yq upgrade > /dev/null 2>&1
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
  lsb-release \
  software-properties-common \
  pipx > /dev/null 2>&1
checkreturncode $? "Base packages installation"

if [[ ! -f /etc/apt/sources.list.d/docker.list ]]; then
  subtitle "Docker installation"
  install -m 0755 -d /etc/apt/keyrings > /dev/null 2>&1
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg > /dev/null 2>&1
  chmod a+r /etc/apt/keyrings/docker.gpg > /dev/null 2>&1
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" > /etc/apt/sources.list.d/docker.list
  apt-get update -qq > /dev/null 2>&1
  apt-get -yq install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin > /dev/null 2>&1
  checkreturncode $? "Docker installation"
  systemctl enable docker >/dev/null 2>&1
  systemctl start docker >/dev/null 2>&1
  checkreturncode $? "Docker service start"
fi

subtitle "Initializing pipx environment"
pipx ensurepath > /dev/null 2>&1
echo "\$PATH=\$PATH:/root/.local/bin" >> /etc/environment > /dev/null 2>&1

pipx install pwgen > /dev/null 2>&1

subtitle "Installing Oh My Zsh"
if [[ ! -d "/root/.oh-my-zsh" ]]; then
  export RUNZSH=no
  export CHSH=no
  sh -c "$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)" -- --unattended > /dev/null 2>&1
  echo 'export PATH=$PATH:~/.local/bin' >> /root/.zshrc > /dev/null 2>&1
fi
if [ "$SHELL" != "/usr/bin/zsh" ]; then
  chsh -s /usr/bin/zsh root
fi

installphp

deployfpmpool

subtitle "Installing Nginx from official repository"
# NGINX_KEYRING="/usr/share/keyrings/nginx-archive-keyring.gpg"
# if [ ! -f "$NGINX_KEYRING" ]; then
#   curl -fsSL https://nginx.org/keys/nginx_signing.key | gpg --dearmor | tee "$NGINX_KEYRING" > /dev/null 2>&1
# fi

# if ! grep -q "nginx.org/packages" /etc/apt/sources.list.d/nginx.list 2>/dev/null; then
#   DISTRO_CODENAME=$(lsb_release -cs)
#   echo "deb [signed-by=$NGINX_KEYRING] http://nginx.org/packages/mainline/ubuntu $DISTRO_CODENAME nginx" > /etc/apt/sources.list.d/nginx.list
#   apt-get update > /dev/null 2>&1
# fi

apt-get -yq install nginx-extras libnginx-mod-http-brotli-filter libnginx-mod-http-brotli-static > /dev/null 2>&1
if ! systemctl is-active --quiet nginx; then
  systemctl enable nginx > /dev/null 2>&1
  systemctl start nginx > /dev/null 2>&1
fi
checkreturncode $? "Nginx installation"

subtitle "Optimizing Nginx configuration (gzip, performance & security)"
rm -f /etc/nginx/conf.d/default.conf > /dev/null 2>&1
rm -f /etc/nginx/sites-available/default > /dev/null 2>&1
rm -f /etc/nginx/sites-enabled/default > /dev/null 2>&1

NGINX_CONF_CONFIG_URL="https://gist.githubusercontent.com/bilyboy785/7965e619604846e96a284b6a5f962242/raw/05b51ecb698f65ba434e6124c3e71147cef547cd/nginx.conf"
curl -fsSL "$NGINX_CONF_CONFIG_URL" -o /etc/nginx/nginx.conf
checkreturncode $? "Nginx base config"

NGINX_OPTIM_CONFIG_URL="https://gist.githubusercontent.com/bilyboy785/7965e619604846e96a284b6a5f962242/raw/2310bb397f428733a4aab3edb1b3797c37d9820c/nginx.optim.conf"
curl -fsSL "$NGINX_OPTIM_CONFIG_URL" -o /etc/nginx/conf.d/optim.conf
checkreturncode $? "Nginx optimization configuration optimization"

NGINX_CACHE_CONFIG_URL="https://gist.githubusercontent.com/bilyboy785/7965e619604846e96a284b6a5f962242/raw/4d2dae4b40eec26070b79a6a53263b6b4f172727/nginx.cache.conf"
curl -fsSL "$NGINX_CACHE_CONFIG_URL" -o /etc/nginx/snippets/cache.conf
checkreturncode $? "Nginx cache configuration optimization"

NGINX_SECURITY_CONFIG_URL="https://gist.githubusercontent.com/bilyboy785/7965e619604846e96a284b6a5f962242/raw/4d2dae4b40eec26070b79a6a53263b6b4f172727/nginx.security.conf"
curl -fsSL "$NGINX_SECURITY_CONFIG_URL" -o /etc/nginx/snippets/security.conf
checkreturncode $? "Nginx security configuration optimization"

sed -i 's/^worker_processes .*/worker_processes auto;/' /etc/nginx/nginx.conf
sed -i 's/^worker_connections .*/worker_connections 4096;/' /etc/nginx/nginx.conf || true
if ! grep -q 'worker_connections' /etc/nginx/nginx.conf; then
  sed -i '/events {/a \    worker_connections 4096;' /etc/nginx/nginx.conf
fi
if systemctl is-active --quiet nginx; then
  systemctl reload nginx > /dev/null 2>&1
fi

nginxcheck

subtitle "Configuring Nginx vhost for WordPress site"

# DNS verification: the domain and aliases must point to the server's IP
SERVER_IP=$(curl -s https://api.ipify.org)
ALL_DOMAINS=("$DOMAIN_NAME")
for dom in "${ALL_DOMAINS[@]}"; do
  [ -z "$dom" ] && continue
  DOMAIN_IPS=$(dig +short A "$dom" | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}')
  if ! echo "$DOMAIN_IPS" | grep -q "$SERVER_IP"; then
    echo "❌ Warning: $dom does not point to the server's IP ($SERVER_IP). Check DNS configuration before continuing."
    read -rp "Press Enter to continue anyway, or Ctrl+C to cancel..."
  fi
done

nginxhttpvhost

subtitle "Generating strong dhparam for nginx SSL"
if [ ! -f /etc/nginx/ssl/dhparam.pem ]; then
  openssl dhparam -out /etc/nginx/ssl/dhparam.pem 4096 > /dev/null 2>&1 &
  checkreturncode $? "DHParam generation"
fi

nginxcheck

subtitle "Setting up WordPress cache directory and webroot"
chown -R ${SYSTEM_USER}:www-data /var/www/${DOMAIN_NAME} > /dev/null 2>&1
chmod 755 /var/www/${DOMAIN_NAME} > /dev/null 2>&1
if ! grep -q "/var/cache/nginx" /etc/fstab; then
  echo "tmpfs /var/cache/nginx tmpfs rw,size=512M,uid=$(id -u www-data),gid=$(id -g www-data),mode=0755 0 0" >> /etc/fstab
  checkreturncode $? "Fstab entry for WordPress cache directory"
fi
mkdir -p /var/cache/nginx/ > /dev/null 2>&1
chown www-data:www-data /var/www/letsencrypt > /dev/null 2>&1
chmod 0755 /var/cache/nginx > /dev/null 2>&1
systemctl daemon-reload > /dev/null 2>&1
mountpoint -q /var/cache/nginx || mount /var/cache/nginx > /dev/null 2>&1
mkdir -p /var/cache/nginx/${DOMAIN_NAME} > /dev/null 2>&1
chown www-data:www-data /var/cache/nginx/${DOMAIN_NAME} > /dev/null 2>&1
if systemctl is-active --quiet nginx; then
  systemctl reload nginx > /dev/null 2>&1
fi
checkreturncode $? "WordPress cache directory and webroot setup"

subtitle "Installing and configuring MariaDB"
if  [[ ! -f /etc/apt/sources.list.d/mariadb.list ]]; then
  curl -fsSL https://mariadb.org/mariadb_release_signing_key.asc | gpg --dearmor -o /usr/share/keyrings/mariadb-keyring.gpg > /dev/null 2>&1
  UBUNTU_CODENAME=$(lsb_release -cs)
  echo "deb [signed-by=/usr/share/keyrings/mariadb-keyring.gpg] https://mirror.mariadb.org/repo/10.11/ubuntu $UBUNTU_CODENAME main" > /etc/apt/sources.list.d/mariadb.list
  apt-get update > /dev/null 2>&1
  apt-get -y install mariadb-server mariadb-client > /dev/null 2>&1
  systemctl enable mariadb > /dev/null 2>&1
  systemctl start mariadb > /dev/null 2>&1
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
ufw --force enable > /dev/null
checkreturncode $? "UFW firewall configuration"

subtitle "Installing backups tools: BorgBackup + Borgmatic"
pipx install borgbackup > /dev/null 2>&1
pipx install borgmatic > /dev/null 2>&1

BORGMATIC_CONFIG_URL="https://gist.githubusercontent.com/bilyboy785/7965e619604846e96a284b6a5f962242/raw/7ff38e32644ea5109e59286d85726c8b5d73a289/borgmatic.config.yaml"
TMP_BORGMATIC_CONF="/tmp/borgmatic.config.yaml"
curl -fsSL "$BORGMATIC_CONFIG_URL" -o "$TMP_BORGMATIC_CONF"
export HOSTNAME
envsubst '$HOSTNAME' < "$TMP_BORGMATIC_CONF" > /etc/borgmatic/config.yaml
rm -f "$TMP_BORGMATIC_CONF"
borgmatic config validate > /dev/null 2>&1
checkreturncode $? "Borgmatic configuration validation"
borgmatic repo-create > /dev/null 2>&1
checkreturncode $? "Borgmatic repository creation"
if [[ ! -f /etc/cron.d/borgmatic ]]; then
  echo "0 2 * * * /root/.local/bin/borgmatic --syslog-verbosity 1 --log-file /var/log/borgmatic/backup.log" > /etc/cron.d/borgmatic
fi
checkreturncode $? "Borgmatic crontab setup"

subtitle "Initial backup with Borgmatic"
borgmatic create --stats > /dev/null 2>&1
checkreturncode $? "Initial backup with Borgmatic"

subtitle "Installing bpytop"
pipx install bpytop > /dev/null 2>&1
checkreturncode $? "Bpytop installation"

subtitle "Installing Certbot and generating Let's Encrypt certificate"
pipx install certbot > /dev/null 2>&1
pipx inject certbot certbot-dns-cloudflare > /dev/null 2>&1
checkreturncode $? "Certbot installation"

subtitle "Installing WP-CLI"
if [ ! -f /usr/local/bin/wp ]; then
  curl -s -o /usr/local/bin/wp https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar > /dev/null 2>&1
  chmod +x /usr/local/bin/wp > /dev/null 2>&1
  wp --info > /dev/null 2>&1 || { echo "❌ L'installation de WP-CLI a échoué"; exit 1; }
  checkreturncode $? "WP-CLI installation"
fi

generateletsencryptcert

nginxhttpsvhost

sed -i 's/# export PATH/export PATH/g' /root/.zshrc

# scriptexpandcertificate

resume

echo "initialized" > /opt/initialized.flag