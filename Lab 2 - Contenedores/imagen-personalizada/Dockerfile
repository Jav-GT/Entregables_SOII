FROM php:8.1-apache
RUN apt-get update && apt-get install -y \
        libfreetype6-dev \
        libjpeg62-turbo-dev \
        libmcrypt-dev \
        libicu-dev \
        libxml2-dev \
        vim \
        wget \
        unzip \
    && docker-php-ext-install -j$(nproc) iconv intl opcache \
    && docker-php-ext-install -j$(nproc) gd \
    && docker-php-ext-install pdo_mysql exif gettext mysqli
