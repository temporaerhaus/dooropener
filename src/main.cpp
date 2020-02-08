#define ETH_CLK_MODE    ETH_CLOCK_GPIO17_OUT

/* 
   * ETH_CLOCK_GPIO0_IN   - default: external clock from crystal oscillator
   * ETH_CLOCK_GPIO0_OUT  - 50MHz clock from internal APLL output on GPIO0 - possibly an inverter is needed for LAN8720
   * ETH_CLOCK_GPIO16_OUT - 50MHz clock from internal APLL output on GPIO16 - possibly an inverter is needed for LAN8720
   * ETH_CLOCK_GPIO17_OUT - 50MHz clock from internal APLL inverted output on GPIO17 - tested with LAN8720
*/

#include <Arduino.h>
#include <HTTPClient.h>
#include <ETH.h>
#include "config.h"

static bool eth_connected = false;

void WiFiEvent(WiFiEvent_t event) {
  switch (event) {
    case SYSTEM_EVENT_ETH_START:
      Serial.println("ETH Started");
      ETH.setHostname("dooropener-salon");
      break;

    case SYSTEM_EVENT_ETH_CONNECTED:
      Serial.println("ETH Connected");
      break;

    case SYSTEM_EVENT_ETH_GOT_IP:
      Serial.print("ETH MAC: ");
      Serial.print(ETH.macAddress());
      Serial.print(", IPv4: ");
      Serial.print(ETH.localIP());
      if (ETH.fullDuplex()) {
        Serial.print(", FULL_DUPLEX");
      }
      Serial.print(", ");
      Serial.print(ETH.linkSpeed());
      Serial.println("Mbps");
      eth_connected = true;
      break;

    case SYSTEM_EVENT_ETH_DISCONNECTED:
      Serial.println("ETH Disconnected");
      eth_connected = false;
      break;

    case SYSTEM_EVENT_ETH_STOP:
      Serial.println("ETH Stopped");
      eth_connected = false;
      break;

    default:
      break;
  }
}

void setup() {
  #ifdef ARDUINO_ESP32_EVB
    // setup relais
    pinMode(RELAIS_0, OUTPUT);
    pinMode(RELAIS_1, OUTPUT);
  #endif

  // for logging
  Serial.begin(115200);

  // connect to network
  Serial.println("Setting up Network...");
  ETH.begin();

  /*
  while (ETH.localIP().toString() == "0.0.0.0") {
    Serial.print(".");
    delay(500);
  }

  Serial.print("Connected. IP=");
  Serial.println(ETH.localIP());
  */

  #ifdef ARDUINO_ESP32_EVB
    // open serial port to nfc reader
    Serial1.begin(9600);

    // initialize rng
    Serial.println(esp_random());

    serverSocket.begin();
  #else
    nfc.begin();

    while (1) {
      uint32_t versiondata = nfc.getFirmwareVersion();

      if (!versiondata) {
        Serial.print("Didn't find PN53x board");
      } else {
        Serial.print("Found chip PN5"); Serial.println((versiondata>>24) & 0xFF, HEX);
        Serial.print("Firmware ver. "); Serial.print((versiondata>>16) & 0xFF, DEC);
        Serial.print('.'); Serial.println((versiondata>>8) & 0xFF, DEC);
        break;
      }
    }

    nfc.SAMConfig();
  #endif

  Serial.println("ready...");
}

void loop() {
  uint8_t success;
  uint8_t uid[] = { 0, 0, 0, 0, 0, 0, 0 };
  uint8_t uidLength = 0;

  #ifdef ARDUINO_ESP32_EVB
    WiFiClient client = serverSocket.available();

    if (client) {
      Serial.println("connected");
      uint32_t rand = esp_random();
      uint8_t* nonce = (uint8_t*) &rand;
      Serial.println("gen_nonce");

      client.write(nonce, 4);
      Serial.println("send_nonce");

      // give backend one second to reply
      delay(300);

      // read backend response
      uint8_t response[37];
      for (uint8_t i = 0; i < 37; i += 1) {
        response[i] = client.read();
      }

      uint8_t status = 0;

      Serial.println("validate hmac");
      // validate that the same nonce was used
      if (memcmp(nonce, response + 1, 4) != 0) {
        status = 1;
      } else {
        // compute hmac of payload
        byte hmacResult[32];

        mbedtls_md_context_t ctx;
        mbedtls_md_type_t md_type = MBEDTLS_MD_SHA256;

        mbedtls_md_init(&ctx);
        mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(md_type), 1);
        mbedtls_md_hmac_starts(&ctx, (const unsigned char *) key, keyLength);
        mbedtls_md_hmac_update(&ctx, (const unsigned char *) response, 5);
        mbedtls_md_hmac_finish(&ctx, hmacResult);
        mbedtls_md_free(&ctx);

        // verify the hmac
        if (memcmp(hmacResult, response + 5, 32) != 0) {
          status = 1;
        } else {
      Serial.println("open");
          // toggle relais if successful
          uint8_t relais = RELAIS_0;
          if (response[0] == 1) {
            relais = RELAIS_1;
          }

          digitalWrite(relais, HIGH);
          delay(1000);
          digitalWrite(relais, LOW);
        }
      }

      client.write(status);
      client.stop();
    }

    // check for new data from nfc reader
    if (Serial1.available() > 0) {
      uidLength = max(0, min(Serial1.read(), 7));
      Serial1.readBytes(uid, uidLength);
      success = 1;
    } else {
      success = 0;
    }
  #else
    success = nfc.readPassiveTargetID(PN532_MIFARE_ISO14443A, uid, &uidLength);
  #endif

  if (success && uidLength > 0) {
    // convert uid to hex string
    char rfiduid[uidLength * 2 + 1];
    for (uint8_t i = 0; i < uidLength; i += 1) {
      byte nib1 = (uid[i] >> 4) & 0x0F;
      byte nib2 = (uid[i] >> 0) & 0x0F;
      rfiduid[i*2+0] = nib1 < 0xA ? '0' + nib1 : 'a' + nib1 - 0xA;
      rfiduid[i*2+1] = nib2 < 0xA ? '0' + nib2 : 'a' + nib2 - 0xA;
    }
    rfiduid[uidLength*2] = '\0';

    Serial.print("card detected -> ");
    Serial.print(authEndpoint);
    Serial.println(rfiduid);

    HTTPClient http;
    WiFiClient client;

    // submit read uid to backend
    Serial.println("start request");
    http.begin(client, authEndpoint + rfiduid);
    Serial.println("response");
    int httpCode = http.GET();

    // debug output
    if (httpCode > 0) {
      String payload = http.getString();
      Serial.println(payload);
    } else {
      Serial.print("HTTP Error: ");
      Serial.println(httpCode);
    }

    http.end();

    // debounce card reading
    delay(debounceTime);
  }

  delay(1);
}