drop TABLE if exists `user`;
drop TABLE if exists `aes_keys`;
drop TABLE if exists `cert`;
create TABLE user(
    `id` INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    `username` VARCHAR(20) NOT NULL,
    `password` VARCHAR(80) NOT NULL
);
create TABLE aes_keys(
    `username` VARCHAR(20) NOT NULL PRIMARY KEY,
    `key` VARCHAR(200) NOT NULL
);
create TABLE cert(
    `username` VARCHAR(20) NOT NULL PRIMARY KEY,
    `serial` VARCHAR(50) NOT NULL,
    `cert` TEXT NOT NULL
)