DROP SEQUENCE IF EXISTS user_credentials_id_seq CASCADE;

DROP TABLE IF EXISTS user_credentials CASCADE;

CREATE TABLE user_credentials (
  id SERIAL,
  username VARCHAR(100),
  user_password VARCHAR,
  oauth2_idp VARCHAR(50),
  user_role VARCHAR(20)
);

INSERT INTO user_credentials (username, user_password, user_role)
VALUES ('user01@domain.com', '$2y$10$R.AVbuzy7f7Vijnj94DF1.7aI8C7V4Zwbf2FWAWk2dCRC3n1iOkbG', 'USER');

INSERT INTO user_credentials (username, user_password, user_role)
VALUES ('user02@domain.com', '$2y$10$SfJCRbSkbM.ObOJHvVCRNuxdrY13loabTM8ROaGW1kBCWJHhI/iZ6', 'USER');

INSERT INTO user_credentials (username, user_password, user_role)
VALUES ('user03@domain.com', '$2y$10$Snb12fzwuYwQY/5zxZTFDer0UK1.RyAVnzCqVVzcF8sF6OF6pdCAm', 'USER');

INSERT INTO user_credentials (username, oauth2_idp, user_role)
VALUES ('user04@gmail.com', 'GOOGLE', 'USER');