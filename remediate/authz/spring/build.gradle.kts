plugins {
    kotlin("jvm") version "2.0.21"
    kotlin("plugin.spring") version "2.0.21"
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

    // Spring Framework & Security
    compileOnly("org.springframework.boot:spring-boot-autoconfigure:$springBootVersion")
    compileOnly("org.springframework.security:spring-security-core:$springSecurityVersion")
    compileOnly("org.springframework.security:spring-security-oauth2-jose:$springSecurityVersion")
    compileOnly("org.springframework.security:spring-security-oauth2-resource-server:$springSecurityVersion")
    compileOnly("org.springframework.data:spring-data-commons:3.3.4")
    compileOnly("org.springframework:spring-aspects:6.1.13")
    compileOnly("org.aspectj:aspectjweaver:1.9.25.1")
    compileOnly("jakarta.servlet:jakarta.servlet-api:6.0.0")

    // Logging
    implementation("org.slf4j:slf4j-api:2.0.20")

    // Test dependencies
    testImplementation(kotlin("test"))
    testImplementation("org.junit.jupiter:junit-jupiter:5.10.3")
    testImplementation("io.mockk:mockk:1.13.12")
    testImplementation("org.springframework.boot:spring-boot-starter-test:$springBootVersion")
    testImplementation("org.springframework.security:spring-security-test:$springSecurityVersion")
    testImplementation("org.springframework.security:spring-security-core:$springSecurityVersion")
    testImplementation("org.springframework.security:spring-security-oauth2-jose:$springSecurityVersion")
    testImplementation("org.springframework.security:spring-security-oauth2-resource-server:$springSecurityVersion")
    testImplementation("org.springframework.data:spring-data-commons:3.3.4")
    testImplementation("org.springframework:spring-aspects:6.1.13")
    testImplementation("org.aspectj:aspectjweaver:1.9.25.1")
}

tasks.test {
    useJUnitPlatform()
}
