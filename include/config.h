// http endpoint to submit scanned UIDs
const String authEndpoint = "http://BACKEND/open?token=TOKEN&door=X&uid=";

// time to wait until next UID is read
const int debounceTime = 3000;

#ifdef ARDUINO_ESP32_EVB
  #include <mbedtls/md.h>

  // shared secret between relais board and backend for hmac
  const size_t keyLength = 32;
  const uint8_t key[] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

  // relais hardware pins
  #define RELAIS_0 32
  #define RELAIS_1 33

  WiFiServer serverSocket(5555);
#else
  #include <SPI.h>
  #include <Adafruit_PN532.h>

  // spi setup for PN532 board
  #define PN532_SS 5
  #define PN532_SCK 14
  #define PN532_MOSI 2
  #define PN532_MISO 15

  Adafruit_PN532 nfc(PN532_SCK, PN532_MISO, PN532_MOSI, PN532_SS);
#endif