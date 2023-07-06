#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/hmac.h>
#include <time.h>
#include <unistd.h>

#define DIGEST_LENGTH 20
#define INTERVAL 30

void hmac_sha1(const unsigned char *key, int key_len, const unsigned char *message, int message_len, unsigned char *digest) {
    HMAC_CTX *ctx = HMAC_CTX_new();

    HMAC_Init_ex(ctx, key, key_len, EVP_sha1(), NULL);
    HMAC_Update(ctx, message, message_len);
    HMAC_Final(ctx, digest, NULL);

    HMAC_CTX_free(ctx);
}

unsigned int generate_otp(const unsigned char *key) {
    time_t current_time;
    unsigned char message[8];
    unsigned char digest[DIGEST_LENGTH];

    current_time = time(NULL);
    snprintf(message, sizeof(message), "%ld", (long)current_time / INTERVAL);

    hmac_sha1(key, strlen(key), message, strlen(message), digest);

    unsigned int otp = (digest[19] & 0xf) << 24 |
                       (digest[16] & 0xff) << 16 |
                       (digest[13] & 0xff) << 8 |
                       (digest[10] & 0xff);

    return otp % 1000000;
}

int kbhit() {
    struct timeval tv;
    fd_set read_fd;

    tv.tv_sec = 0;
    tv.tv_usec = 0;
    FD_ZERO(&read_fd);
    FD_SET(STDIN_FILENO, &read_fd);

    if (select(STDIN_FILENO + 1, &read_fd, NULL, NULL, &tv) == -1)
        return 0;

    if (FD_ISSET(STDIN_FILENO, &read_fd))
        return 1;

    return 0;
}

int main() {
    char key[100];

    printf("Press 'q' or 'Q' to quit.\n");
    printf("Enter your secret key: ");
    fgets(key, sizeof(key), stdin);

    key[strcspn(key, "\n")] = '\0'; // Remove newline character from key

    while (1) {
        unsigned int otp = generate_otp(key);
        printf("Generated OTP: %06u\n", otp);
        printf("Waiting for 30 seconds...\n");

        time_t start_time = time(NULL);
        while (time(NULL) - start_time < INTERVAL) {
            if (kbhit()) {
                fgets(key, sizeof(key), stdin);
                if (key[0] == 'q' || key[0] == 'Q') {
                    return 0;
                }
            }
            usleep(10000); // Sleep for 10 milliseconds
        }
    }

    return 0;
}
