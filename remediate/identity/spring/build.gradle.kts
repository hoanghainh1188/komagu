plugins {
    kotlin("jvm") version "2.4.21"
    kotlin("plugin.spring") version "2.4.21"
    `java-library`
    `maven-publish`
}

group = "io.komainu"
version = "1.0.0-SNAPSHOT"

repositories {
    mavenCentral()
}

java {
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(17))
    }
}

val springBootVersion = "3.3.4"
val springSecurityVersion = "6.3.3"

dependencies {
    implementation("org.jetbrains.kotlin:kotlin-reflect")
    implementation("org.jetbrains.kotlin:kotlin-stdlib-jdk8")

    // Spring Boot & Security
    compileOnly("org.springframework.boot:spring-boot-autoconfigure:$springBootVersion")
    compileOnly("org.springframework.boot:spring-boot-configuration-processor:$springBootVersion")
    compileOnly("org.springframework.security:spring-security-config:$springSecurityVersion")
    compileOnly("org.springframework.security:spring-security-web:$springSecurityVersion")
    compileOnly("org.springframework.security:spring-security-oauth2-resource-server:$springSecurityVersion")
    compileOnly("org.springframework.security:spring-security-oauth2-jose:$springSecurityVersion")
    compileOnly("jakarta.servlet:jakarta.servlet-api:6.0.0")

    // Logging
    implementation("org.slf4j:slf4j-api:2.0.20")

    // Test dependencies
    testImplementation(kotlin("test"))
    testImplementation("org.junit.jupiter:junit-jupiter:5.10.3")
    testImplementation("io.mockk:mockk:1.13.12")
    testImplementation("org.springframework.boot:spring-boot-starter-test:$springBootVersion")
    testImplementation("org.springframework.boot:spring-boot-starter-web:$springBootVersion")
    testImplementation("org.springframework.security:spring-security-test:$springSecurityVersion")
    testImplementation("org.springframework.security:spring-security-config:$springSecurityVersion")
    testImplementation("org.springframework.security:spring-security-web:$springSecurityVersion")
    testImplementation("org.springframework.security:spring-security-oauth2-resource-server:$springSecurityVersion")
    testImplementation("org.springframework.security:spring-security-oauth2-jose:$springSecurityVersion")
}

tasks.test {
    useJUnitPlatform()
}
