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
      ETH.begin();
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
  WiFi.onEvent(WiFiEvent);
  ETH.begin();

  #ifdef ARDUINO_ESP32_EVB
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
  #ifdef ARDUINO_ESP32_EVB
    WiFiClient client = serverSocket.available();

    if (client) {
      uint32_t rand = esp_random();
      Serial.print("sending nonce: ");
      Serial.println(rand);

      uint8_t* nonce = (uint8_t*) &rand;
      client.write(nonce, 4);

      // give backend one second to reply
      delay(300);

      // read backend response
      uint8_t response[37];
      for (uint8_t i = 0; i < 37; i += 1) {
        response[i] = client.read();
      }

      Serial.println("received response");

      uint8_t status = 0;

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
          Serial.println("toggling relais");

          // toggle relais if successful
          uint8_t relais = response[0] == 1 ? RELAIS_0 : RELAIS_1;

          digitalWrite(relais, HIGH);
          delay(1000);
          digitalWrite(relais, LOW);
        }
      }

      client.write(status);
      client.stop();
      Serial.println("disconnecting client");
    }
  #else
    uint8_t uid[] = { 0, 0, 0, 0, 0, 0, 0 };
    uint8_t uidLength = 0;

    uint8_t success = nfc.readPassiveTargetID(PN532_MIFARE_ISO14443A, uid, &uidLength);

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
  #endif

  delay(1);
}