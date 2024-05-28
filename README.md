# BudgetBuddy Authentication Service

## Overview

The Authentication Service handles user registration and login, both via username and password and Google as an OAuth2 authorization server.

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [API Documentation](#api-documentation)
- [Testing](#testing)


## Architecture

The Authentication Service is built with the following technologies:
- **Backend**: Spring Boot
- **Database**: PostgreSQL
- **Testing**: JUnit & MockMVC
- **Communication**: REST APIs

## Installation

### Prerequisites

- JDK 17
- Maven
- PostgreSQL database

### Steps

1. Clone the repository:
    ```bash
    git clone https://github.com/{your_username}/authservice.git
    cd authservice
    ```

2. Build the project:
    ```bash
    mvn clean install
    ```

3. Run the application:
    ```bash
    mvn spring-boot:run
    ```

## Configuration

Configure your database and other settings in the `application.yml` file located in `src/main/resources`:

```yaml
spring:
  datasource:
    url: jdbc:mysql://{database_url}:{port}/{db_name}
    username: {db_username}
    password: {db_password}
  jpa:
    hibernate:
      ddl-auto: update
```
`ddl-auto` generates tables whenever you start the application and should only be used for testing purposes. To disable it, set the value to `none`.

## Usage

You can access the authentication endpoints using tools like Postman or `curl`.

To run the tests, use the following command:

```bash
mvn test
```

## API Documentation

### Endpoints

#### Register
- **URL**: ```POST /auth/register```
- **Description**: Create a new account by providing a username (email address) & password.
- **Request**:
    ```javascript
    {
      "username": "newuser@email.com"
      "password": "correcthorsebatterystaple"
    }
    ```
- **Response (201 CREATED)**:
    Empty body.

#### Login
- **URL**: ```POST /auth/login```
- **Description**: Log in by providing a username & password.
- **Request**:
    ```javascript
    {
      "username": "newuser@email.com"
      "password": "correcthorsebatterystaple"
    }
    ```
- **Response (200 OK)**:
    ```javascript
      {
        "username": "newuser@email.com",
        "password": null
      }
    ```

#### Login with OAuth2
- **URL**: ```GET /auth/login/oauth2```
- **Description**: Redirect to the Google authorization flow to log in.
- **Response**:
   Redirection to the home page after successful authorization.

#### JWT Validation
- **URL**: ```GET /auth/validate```
- **Description**: Validates a JWT by decoding it and returning the subject (username) and user ID (claim).
- **Response (200 OK)**:
  ```javascript
    {
      "jwtSubject": "user01@domain.com",
      "jwtClaim": "1"
    }
  ```

#### Logout
- **URL**: ```GET /auth/logout}```
- **Description**: Log out by deleting the JWT stored as a cookie and closing any active sessions on the server.
- **Response (200 OK)**:
    Redirect to the home page.

## Built With
![](https://img.shields.io/badge/-Java-007396?style=flat-square&logo=java&logoColor=white)
![](https://img.shields.io/badge/-Spring_Boot-6DB33F?style=flat-square&logo=spring-boot&logoColor=white)
![Spring Security](https://img.shields.io/badge/-Spring_Security-6DB33F?style=flat-square&logo=spring-security&logoColor=white)
![](https://img.shields.io/badge/-PostgreSQL-4169E1?style=flat-square&logo=postgresql&logoColor=white)
![JUnit](https://img.shields.io/badge/-JUnit-25A162?style=flat-square&logo=junit5&logoColor=white)
![Docker](https://img.shields.io/badge/-Docker-2496ED?style=flat-square&logo=docker&logoColor=white)
![AWS](https://img.shields.io/badge/-AWS-232F3E?style=flat-square&logo=amazon-aws&logoColor=white)
![Maven](https://img.shields.io/badge/-Maven-C71A36?style=flat-square&logo=apache-maven&logoColor=white)
![Eureka](https://img.shields.io/badge/-Eureka-239D60?style=flat-square&logo=spring&logoColor=white)
![Microservices](https://img.shields.io/badge/-Microservices-000000?style=flat-square&logo=cloud&logoColor=white)
