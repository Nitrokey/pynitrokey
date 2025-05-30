/*
 * Copyright (c) 2015-2018 Nitrokey UG
 *
 * This file is part of libnitrokey.
 *
 * libnitrokey is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * any later version.
 *
 * libnitrokey is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with libnitrokey. If not, see <http://www.gnu.org/licenses/>.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

#ifndef LIBNITROKEY_NK_C_API_H
#define LIBNITROKEY_NK_C_API_H

#include <stdbool.h>
#include <stdint.h>

#include "deprecated.h"

#ifdef _MSC_VER
#define NK_C_API __declspec(dllexport)
#else
#define NK_C_API
#endif

/**
 * \file
 *
 * C API for libnitrokey
 *
 * \mainpage
 *
 * **libnitrokey** provides access to Nitrokey Pro and Nitrokey Storage devices.
 * This documentation describes libnitrokey’s C API.  For a list of the
 * available functions, see the NK_C_API.h file.
 *
 * \section getting_started Example
 *
 * \code{.c}
 * #include <stdio.h>
 * #include <stdlib.h>
 * #include <libnitrokey/NK_C_API.h>
 *
 * int main(void)
 * {
 *         if (NK_login_auto() != 1) {
 *                 fprintf(stderr, "No Nitrokey found.\n");
 *                 return 1;
 *         }
 *
 *         NK_device_model model = NK_get_device_model();
 *         printf("Connected to ");
 *         switch (model) {
 *         case NK_PRO:
 *                 printf("a Nitrokey Pro");
 *                 break;
 *         case NK_STORAGE:
 *                 printf("a Nitrokey Storage");
 *                 break;
 *         case NK_LIBREM:
 *                 printf("a Librem Key");
 *                 break;
 *         default:
 *                 printf("an unsupported Nitrokey");
 *                 break;
 *         }
 *
 *         char* serial_number = NK_device_serial_number();
 *         if (serial_number)
 *             printf(" with serial number %s\n", serial_number);
 *         else
 *             printf(" -- could not query serial number!\n");
 *         free(serial_number);
 *
 *         NK_logout();
 *         return 0;
 * }
 * \endcode
 */

#ifdef __cplusplus
extern "C" {
#endif

  /**
   * The number of slots in the password safe.
   */
  extern const uint8_t NK_PWS_SLOT_COUNT;

  static const int MAXIMUM_STR_REPLY_LENGTH = 8192;

        /**
         * The Nitrokey device models supported by the API.
         */
        enum NK_device_model {
						/**
						 * Use, if no supported device is connected
						 */
        		NK_DISCONNECTED = 0,
            /**
             * Nitrokey Pro.
             */
            NK_PRO = 1,
            /**
             * Nitrokey Storage.
             */
            NK_STORAGE = 2,
            /**
             * Librem Key.
             */
            NK_LIBREM = 3
        };

        /**
	 * The connection info for a Nitrokey device as a linked list.
	 */
	struct NK_device_info {
		/**
		 * The model of the Nitrokey device.
		 */
		enum NK_device_model model;
		/**
		 * The USB device path for NK_connect_with_path.
		 */
		char* path;
		/**
		 * The serial number.
		 */
		char* serial_number;
		/**
		 * The pointer to the next element of the linked list or null
		 * if this is the last element in the list.
		 */
		struct NK_device_info* next;
	};

	/**
	 * Stores the common device status for all Nitrokey devices.
	 */
	struct NK_status {
		/**
		 * The major firmware version, e. g. 0 in v0.40.
		 */
		uint8_t firmware_version_major;
		/**
		 * The minor firmware version, e. g. 40 in v0.40.
		 */
		uint8_t firmware_version_minor;
		/**
		 * The serial number of the smart card.
		 */
		uint32_t serial_number_smart_card;
		/**
		 * The HOTP slot to generate a password from if the numlock
		 * key is pressed twice (slot 0-1, or any other value to
		 * disable the function).
		 */
		uint8_t config_numlock;
		/**
		 * The HOTP slot to generate a password from if the capslock
		 * key is pressed twice (slot 0-1, or any other value to
		 * disable the function).
		 */
		uint8_t config_capslock;
		/**
		 * The HOTP slot to generate a password from if the scrolllock
		 * key is pressed twice (slot 0-1, or any other value to
		 * disable the function).
		 */
		uint8_t config_scrolllock;
		/**
		 * Indicates whether the user password is required to generate
		 * an OTP value.
		 */
		bool otp_user_password;
	};

	/**
	 * Stores the status of a Storage device.
	 */
        struct NK_storage_status {
		/**
		 * Indicates whether the unencrypted volume is read-only.
		 */
		bool unencrypted_volume_read_only;
		/**
		 * Indicates whether the unencrypted volume is active.
		 */
		bool unencrypted_volume_active;
		/**
		 * Indicates whether the encrypted volume is read-only.
		 */
		bool encrypted_volume_read_only;
		/**
		 * Indicates whether the encrypted volume is active.
		 */
		bool encrypted_volume_active;
		/**
		 * Indicates whether the hidden volume is read-only.
		 */
		bool hidden_volume_read_only;
		/**
		 * Indicates whether the hidden volume is active.
		 */
		bool hidden_volume_active;
		/**
		 * The major firmware version, e. g. 0 in v0.40.
		 */
		uint8_t firmware_version_major;
		/**
		 * The minor firmware version, e. g. 40 in v0.40.
		 */
		uint8_t firmware_version_minor;
		/**
		 * Indicates whether the firmware is locked.
		 */
		bool firmware_locked;
		/**
		 * The serial number of the SD card in the Storage stick.
		 */
		uint32_t serial_number_sd_card;
		/**
		 * The serial number of the smart card in the Storage stick.
		 */
		uint32_t serial_number_smart_card;
		/**
		 * The number of remaining login attempts for the user PIN.
		 */
		uint8_t user_retry_count;
		/**
		 * The number of remaining login attempts for the admin PIN.
		 */
		uint8_t admin_retry_count;
		/**
		 * Indicates whether a new SD card was found.
		 */
		bool new_sd_card_found;
		/**
		 * Indicates whether the SD card is filled with random characters.
		 */
		bool filled_with_random;
		/**
		 * Indicates whether the stick has been initialized by generating
		 * the AES keys.
		 */
		bool stick_initialized;
        };

	/**
	 * Data about the usage of the SD card.
	 */
	struct NK_SD_usage_data {
		/**
		 * The minimum write level, as a percentage of the total card
		 * size.
		 */
		uint8_t write_level_min;
		/**
		 * The maximum write level, as a percentage of the total card
		 * size.
		 */
		uint8_t write_level_max;
	};

        /**
         * The general configuration of a Nitrokey device.
         */
        struct NK_config {
            /**
             * value in range [0-1] to send HOTP code from slot 'numlock' after double pressing numlock
             * or outside the range to disable this function
             */
            uint8_t numlock;
            /**
	     * similar to numlock but with capslock
             */
            uint8_t capslock;
            /**
	     * similar to numlock but with scrolllock
             */
            uint8_t scrolllock;
            /**
             * True to enable OTP PIN protection (require PIN each OTP code request)
             */
            bool enable_user_password;
            /**
             * Unused.
             */
            bool disable_user_password;
        };

   struct NK_storage_ProductionTest{
    uint8_t FirmwareVersion_au8[2];
    uint8_t FirmwareVersionInternal_u8;
    uint8_t SD_Card_Size_u8;
    uint32_t CPU_CardID_u32;
    uint32_t SmartCardID_u32;
    uint32_t SD_CardID_u32;
    uint8_t SC_UserPwRetryCount;
    uint8_t SC_AdminPwRetryCount;
    uint8_t SD_Card_ManufacturingYear_u8;
    uint8_t SD_Card_ManufacturingMonth_u8;
    uint16_t SD_Card_OEM_u16;
    uint16_t SD_WriteSpeed_u16;
    uint8_t SD_Card_Manufacturer_u8;
  };

  NK_C_API int NK_get_storage_production_info(struct NK_storage_ProductionTest * out);


/**
 * Set debug level of messages written on stderr
 * @param state state=True - most messages, state=False - only errors level
 */
	NK_C_API void NK_set_debug(bool state);

	/**
	 * Set debug level of messages written on stderr
	 * @param level (int) 0-lowest verbosity, 5-highest verbosity
	 */
	NK_C_API void NK_set_debug_level(const int level);

	/**
	 * Get the major library version, e. g. the 3 in v3.2.
	 * @return the major library version
	 */
	NK_C_API unsigned int NK_get_major_library_version();

	/**
	 * Get the minor library version, e. g. the 2 in v3.2.
	 * @return the minor library version
	 */
	NK_C_API unsigned int NK_get_minor_library_version();

	/**
	 * Get the library version as a string.  This is the output of
	 * `git describe --always` at compile time, for example "v3.3" or
	 * "v3.3-19-gaee920b".
	 * The return value is a string literal and must not be freed.
	 * @return the library version as a string
	 */
	NK_C_API const char* NK_get_library_version();

	/**
	 * Connect to device of given model. Currently library can be connected only to one device at once.
	 * @param device_model char 'S': Nitrokey Storage, 'P': Nitrokey Pro
	 * @return 1 if connected, 0 if wrong model or cannot connect
	 */
	NK_C_API int NK_login(const char *device_model);

	/**
	 * Connect to device of given model. Currently library can be connected only to one device at once.
	 * @param device_model NK_device_model: NK_PRO: Nitrokey Pro, NK_STORAGE: Nitrokey Storage, NK_LIBREM: Librem Key
	 * @return 1 if connected, 0 if wrong model or cannot connect
	 */
        NK_C_API int NK_login_enum(enum NK_device_model device_model);

	/**
	 * Connect to first available device, starting checking from Pro 1st to Storage 2nd.
	 * @return 1 if connected, 0 if wrong model or cannot connect
	 */
	NK_C_API int NK_login_auto();

	/**
	 * Disconnect from the device.
	 * @return command processing error code
	 */
	NK_C_API int NK_logout();

	/**
	 * Query the model of the connected device.
	 * Returns the model of the connected device or NK_DISCONNECTED.
	 *
	 * @return true if a device is connected and the out argument has been set
	 */
	NK_C_API enum NK_device_model NK_get_device_model();

	/**
	 * Return the debug status string. Debug purposes.  This function is
	 * deprecated in favor of NK_get_status_as_string.
	 * @return string representation of the status or an empty string
	 *         if the command failed
	 */
	DEPRECATED
	NK_C_API char * NK_status();

	/**
	 * Return the debug status string. Debug purposes.
	 * @return string representation of the status or an empty string
	 *         if the command failed
	 */
	NK_C_API char * NK_get_status_as_string();

	/**
	 * Get the stick status common to all Nitrokey devices and return the
	 * command processing error code.  If the code is zero, i. e. the
	 * command was successful, the storage status is written to the output
	 * pointer's target.  The output pointer must not be null.
	 *
	 * @param out the output pointer for the status
	 * @return command processing error code
	 */
	NK_C_API int NK_get_status(struct NK_status* out);

	/**
	 * Return the device's serial number string in hex.
	 * @return string device's serial number in hex
	 */
	NK_C_API char * NK_device_serial_number();

	/**
	 * Return the device's serial number string as an integer.  Use
         * NK_last_command_status to check for an error if this function
         * returns zero.
	 * @return device's serial number as an integer
	 */
	NK_C_API uint32_t NK_device_serial_number_as_u32();

	/**
	 * Get last command processing status. Useful for commands which returns the results of their own and could not return
	 * an error code.
	 * @return previous command processing error code
	 */
	NK_C_API uint8_t NK_get_last_command_status();

	/**
	 * Lock device - cancel any user device unlocking.
	 * @return command processing error code
	 */
	NK_C_API int NK_lock_device();

	/**
	 * Authenticates the user on USER privilages with user_password and sets user's temporary password on device to user_temporary_password.
	 * @param user_password char[25] current user password
	 * @param user_temporary_password char[25] user temporary password to be set on device for further communication (authentication command)
	 * @return command processing error code
	 */
	NK_C_API int NK_user_authenticate(const char* user_password, const char* user_temporary_password);

	/**
	 * Authenticates the user on ADMIN privilages with admin_password and sets user's temporary password on device to admin_temporary_password.
	 * @param admin_password char[25] current administrator PIN
	 * @param admin_temporary_password char[25] admin temporary password to be set on device for further communication (authentication command)
	 * @return command processing error code
	 */
	NK_C_API int NK_first_authenticate(const char* admin_password, const char* admin_temporary_password);

	/**
	 * Execute a factory reset.
	 * @param admin_password char[20] current administrator PIN
	 * @return command processing error code
	 */
	NK_C_API int NK_factory_reset(const char* admin_password);

	/**
	 * Generates AES key on the device
	 * @param admin_password char[20] current administrator PIN
	 * @return command processing error code
	 */
	NK_C_API int NK_build_aes_key(const char* admin_password);

	/**
	 * Unlock user PIN locked after 3 incorrect codes tries.
	 * @param admin_password char[20] current administrator PIN
	 * @return command processing error code
	 */
	NK_C_API int NK_unlock_user_password(const char *admin_password, const char *new_user_password);

	/**
	 * Write general config to the device
	 * @param numlock set value in range [0-1] to send HOTP code from slot 'numlock' after double pressing numlock
	 * or outside the range to disable this function
	 * @param capslock similar to numlock but with capslock
	 * @param scrolllock similar to numlock but with scrolllock
	 * @param enable_user_password set True to enable OTP PIN protection (require PIN each OTP code request)
	 * @param delete_user_password (unused)
	 * @param admin_temporary_password current admin temporary password
	 * @return command processing error code
	 */
	NK_C_API int NK_write_config(uint8_t numlock, uint8_t capslock, uint8_t scrolllock,
		bool enable_user_password, bool delete_user_password, const char *admin_temporary_password);

	/**
	 * Write general config to the device
	 * @param config the configuration data
	 * @param admin_temporary_password current admin temporary password
	 * @return command processing error code
	 */
	NK_C_API int NK_write_config_struct(struct NK_config config, const char *admin_temporary_password);

	/**
	 * Get currently set config - status of function Numlock/Capslock/Scrollock OTP sending and is enabled PIN protected OTP
         * The return value must be freed using NK_free_config.
	 * @see NK_write_config
	 * @return  uint8_t general_config[5]:
	 *            uint8_t numlock;
				  uint8_t capslock;
				  uint8_t scrolllock;
				  uint8_t enable_user_password;
				  uint8_t delete_user_password;

	 */
	NK_C_API uint8_t* NK_read_config();

        /**
         * Free a value returned by NK_read_config.  May be called with a NULL
         * argument.
         */
        NK_C_API void NK_free_config(uint8_t* config);

	/**
	 * Get currently set config and write it to the given pointer.
         * @see NK_read_config
	 * @see NK_write_config_struct
         * @param out a pointer to the struct that should be written to
	 * @return command processing error code
	 */
	NK_C_API int NK_read_config_struct(struct NK_config* out);

	//OTP

	/**
	 * Get name of given TOTP slot
	 * @param slot_number TOTP slot number, slot_number<15
	 * @return char[20] the name of the slot
	 */
	NK_C_API char * NK_get_totp_slot_name(uint8_t slot_number);

	/**
	 *
	 * @param slot_number HOTP slot number, slot_number<3
	 * @return char[20] the name of the slot
	 */
	NK_C_API char * NK_get_hotp_slot_name(uint8_t slot_number);

	/**
	 * Erase HOTP slot data from the device
	 * @param slot_number HOTP slot number, slot_number<3
	 * @param temporary_password admin temporary password
	 * @return command processing error code
	 */
	NK_C_API int NK_erase_hotp_slot(uint8_t slot_number, const char *temporary_password);

	/**
	 * Erase TOTP slot data from the device
	 * @param slot_number TOTP slot number, slot_number<15
	 * @param temporary_password admin temporary password
	 * @return command processing error code
	 */
	NK_C_API int NK_erase_totp_slot(uint8_t slot_number, const char *temporary_password);

	/**
	 * Write HOTP slot data to the device
	 * @param slot_number HOTP slot number, slot_number<3, 0-numbered
	 * @param slot_name char[15] desired slot name. C string (requires ending '\0'; 16 bytes).
	 * @param secret char[40] 160-bit or 320-bit (currently Pro v0.8 only) secret as a hex string. C string (requires ending '\0'; 41 bytes).
	 * See NitrokeyManager::is_320_OTP_secret_supported.
	 * @param hotp_counter uint32_t starting value of HOTP counter
	 * @param use_8_digits should returned codes be 6 (false) or 8 digits (true)
	 * @param use_enter press ENTER key after sending OTP code using double-pressed scroll/num/capslock
	 * @param use_tokenID @see token_ID
	 * @param token_ID @see https://openauthentication.org/token-specs/, 'Class A' section
	 * @param temporary_password char[25] admin temporary password
	 * @return command processing error code
	 */
	NK_C_API int NK_write_hotp_slot(uint8_t slot_number, const char *slot_name, const char *secret, uint64_t hotp_counter,
		bool use_8_digits, bool use_enter, bool use_tokenID, const char *token_ID,
		const char *temporary_password);

	/**
	 * Write TOTP slot data to the device
	 * @param slot_number TOTP slot number, slot_number<15, 0-numbered
	 * @param slot_name char[15] desired slot name. C string (requires ending '\0'; 16 bytes).
	 * @param secret char[40] 160-bit or 320-bit (currently Pro v0.8 only) secret as a hex string. C string (requires ending '\0'; 41 bytes).
	 * See NitrokeyManager::is_320_OTP_secret_supported.
	 * @param time_window uint16_t time window for this TOTP
	 * @param use_8_digits should returned codes be 6 (false) or 8 digits (true)
	 * @param use_enter press ENTER key after sending OTP code using double-pressed scroll/num/capslock
	 * @param use_tokenID @see token_ID
	 * @param token_ID @see https://openauthentication.org/token-specs/, 'Class A' section
	 * @param temporary_password char[20] admin temporary password
	 * @return command processing error code
	 */
	NK_C_API int NK_write_totp_slot(uint8_t slot_number, const char *slot_name, const char *secret, uint16_t time_window,
		bool use_8_digits, bool use_enter, bool use_tokenID, const char *token_ID,
		const char *temporary_password);

	/**
	 * Get HOTP code from the device
	 * @param slot_number HOTP slot number, slot_number<3
	 * @return HOTP code
	 */
	NK_C_API char * NK_get_hotp_code(uint8_t slot_number);

	/**
	 * Get HOTP code from the device (PIN protected)
	 * @param slot_number HOTP slot number, slot_number<3
	 * @param user_temporary_password char[25] user temporary password if PIN protected OTP codes are enabled,
	 * otherwise should be set to empty string - ''
	 * @return HOTP code
	 */
	NK_C_API char * NK_get_hotp_code_PIN(uint8_t slot_number, const char *user_temporary_password);

	/**
	 * Get TOTP code from the device
	 * @param slot_number TOTP slot number, slot_number<15
	 * @param challenge TOTP challenge -- unused
	 * @param last_totp_time last time -- unused
	 * @param last_interval last interval --unused
	 * @return TOTP code
	 */
	NK_C_API char * NK_get_totp_code(uint8_t slot_number, uint64_t challenge, uint64_t last_totp_time,
		uint8_t last_interval);

	/**
	 * Get TOTP code from the device (PIN protected)
	 * @param slot_number TOTP slot number, slot_number<15
	 * @param challenge TOTP challenge -- unused
	 * @param last_totp_time last time -- unused
	 * @param last_interval last interval -- unused
	 * @param user_temporary_password char[25] user temporary password if PIN protected OTP codes are enabled,
	 * otherwise should be set to empty string - ''
	 * @return TOTP code
	 */
	NK_C_API char * NK_get_totp_code_PIN(uint8_t slot_number, uint64_t challenge,
		uint64_t last_totp_time, uint8_t last_interval,
		const char *user_temporary_password);

	/**
	 * Set time on the device (for TOTP requests)
	 * @param time seconds in unix epoch (from 01.01.1970)
	 * @return command processing error code
	 */
	NK_C_API int NK_totp_set_time(uint64_t time);

	/**
	 * Set the device time used for TOTP to the given time.  Contrary to
	 * {@code set_time(uint64_t)}, this command fails if {@code old_time}
	 * &gt; {@code time} or if {@code old_time} is zero (where {@code
	 * old_time} is the current time on the device).
	 *
	 * @param time new device time as Unix timestamp (seconds since
	 *        1970-01-01)
	 * @return command processing error code
	 */
	NK_C_API int NK_totp_set_time_soft(uint64_t time);

	// NK_totp_get_time is deprecated -- use NK_totp_set_time_soft instead
	DEPRECATED
	NK_C_API int NK_totp_get_time();

	//passwords
	/**
	 * Change administrator PIN
	 * @param current_PIN char[25] current PIN
	 * @param new_PIN char[25] new PIN
	 * @return command processing error code
	 */
	NK_C_API int NK_change_admin_PIN(const char *current_PIN, const char *new_PIN);

	/**
	 * Change user PIN
	 * @param current_PIN char[25] current PIN
	 * @param new_PIN char[25] new PIN
	 * @return command processing error code
	*/
	NK_C_API int NK_change_user_PIN(const char *current_PIN, const char *new_PIN);


	/**
	 * Get retry count of user PIN
	 * @return user PIN retry count
	 */
	NK_C_API uint8_t NK_get_user_retry_count();

	/**
	 * Get retry count of admin PIN
	 * @return admin PIN retry count
	 */
	NK_C_API uint8_t NK_get_admin_retry_count();
	//password safe

	/**
	 * Enable password safe access
	 * @param user_pin char[30] current user PIN
	 * @return command processing error code
	 */
	NK_C_API int NK_enable_password_safe(const char *user_pin);

	/**
	 * Get password safe slots' status
         * The return value must be freed using NK_free_password_safe_slot_status.
	 * @return uint8_t[16] slot statuses - each byte represents one slot with 0 (not programmed) and 1 (programmed)
	 */
	NK_C_API uint8_t * NK_get_password_safe_slot_status();

        /**
         * Free a value returned by NK_get_password_safe_slot_status.  May be
         * called with a NULL argument.
         */
        NK_C_API void NK_free_password_safe_slot_status(uint8_t* status);

	/**
	 * Get password safe slot name
	 * @param slot_number password safe slot number, slot_number<16
	 * @return slot name
	 */
	NK_C_API char *NK_get_password_safe_slot_name(uint8_t slot_number);

	/**
	 * Get password safe slot login
	 * @param slot_number password safe slot number, slot_number<16
	 * @return login from the PWS slot
	 */
	NK_C_API char *NK_get_password_safe_slot_login(uint8_t slot_number);

	/**
	 * Get the password safe slot password
	 * @param slot_number password safe slot number, slot_number<16
	 * @return password from the PWS slot
	 */
	NK_C_API char *NK_get_password_safe_slot_password(uint8_t slot_number);

	/**
	 * Write password safe data to the slot
	 * @param slot_number password safe slot number, slot_number<16
	 * @param slot_name char[11] name of the slot
	 * @param slot_login char[32] login string
	 * @param slot_password char[20] password string
	 * @return command processing error code
	 */
	NK_C_API int NK_write_password_safe_slot(uint8_t slot_number, const char *slot_name,
		const char *slot_login, const char *slot_password);

	/**
	 * Erase the password safe slot from the device
	 * @param slot_number password safe slot number, slot_number<16
	 * @return command processing error code
	 */
	NK_C_API int NK_erase_password_safe_slot(uint8_t slot_number);

	/**
	 * Check whether AES is supported by the device
	 * @return 0 for no and 1 for yes
	 */
	NK_C_API int NK_is_AES_supported(const char *user_password);

	/**
	 * Get device's major firmware version
	 * @return major part of the version number (e.g. 0 from 0.48, 0 from 0.7 etc.)
	 */
	NK_C_API uint8_t NK_get_major_firmware_version();

	/**
	 * Get device's minor firmware version
	 * @return minor part of the version number (e.g. 7 from 0.7, 48 from 0.48 etc.)
	 */
	NK_C_API uint8_t NK_get_minor_firmware_version();

  /**
   * Function to determine unencrypted volume PIN type
   * @param minor_firmware_version
   * @return Returns 1, if set unencrypted volume ro/rw pin type is User, 0 otherwise.
   */
	NK_C_API int NK_set_unencrypted_volume_rorw_pin_type_user();


	/**
	 * This command is typically run to initiate
	 * communication with the device (altough not required).
	 * It sets time on device and returns its current status
	 * - a combination of set_time and get_status_storage commands
	 * Storage only
	 * @param seconds_from_epoch date and time expressed in seconds
	 */
	NK_C_API int NK_send_startup(uint64_t seconds_from_epoch);

	/**
	 * Unlock encrypted volume.
	 * Storage only
	 * @param user_pin user pin 20 characters
	 * @return command processing error code
	 */
	NK_C_API int NK_unlock_encrypted_volume(const char* user_pin);

	/**
	 * Locks encrypted volume
	 * @return command processing error code
	 */
	NK_C_API int NK_lock_encrypted_volume();

	/**
	 * Unlock hidden volume and lock encrypted volume.
	 * Requires encrypted volume to be unlocked.
	 * Storage only
	 * @param hidden_volume_password 20 characters
	 * @return command processing error code
	 */
	NK_C_API int NK_unlock_hidden_volume(const char* hidden_volume_password);

	/**
	 * Locks hidden volume
	 * @return command processing error code
	 */
	NK_C_API int NK_lock_hidden_volume();

	/**
	 * Create hidden volume.
	 * Requires encrypted volume to be unlocked.
	 * Storage only
	 * @param slot_nr slot number in range 0-3
	 * @param start_percent volume begin expressed in percent of total available storage, int in range 0-99
	 * @param end_percent volume end expressed in percent of total available storage, int in range 1-100
	 * @param hidden_volume_password 20 characters
	 * @return command processing error code
	 */
	NK_C_API int NK_create_hidden_volume(uint8_t slot_nr, uint8_t start_percent, uint8_t end_percent,
		const char *hidden_volume_password);

	/**
	 * Make unencrypted volume read-only.
	 * Device hides unencrypted volume for a second therefore make sure
	 * buffers are flushed before running.
	 * Does nothing if firmware version is not matched
	 * Firmware range: Storage v0.50, v0.48 and below
	 * Storage only
	 * @param user_pin 20 characters User PIN
	 * @return command processing error code
	 */
  //[[deprecated("Use NK_set_unencrypted_read_only_admin instead")]]
  DEPRECATED
  NK_C_API int NK_set_unencrypted_read_only(const char *user_pin);

	/**
	 * Make unencrypted volume read-write.
	 * Device hides unencrypted volume for a second therefore make sure
	 * buffers are flushed before running.
	 * Does nothing if firmware version is not matched
	 * Firmware range: Storage v0.50, v0.48 and below
	 * Storage only
	 * @param user_pin 20 characters User PIN
	 * @return command processing error code
	 */
  //[[deprecated("Use NK_set_unencrypted_read_write_admin instead")]]
  DEPRECATED
  NK_C_API int NK_set_unencrypted_read_write(const char *user_pin);

	/**
	 * Make unencrypted volume read-only.
	 * Device hides unencrypted volume for a second therefore make sure
	 * buffers are flushed before running.
	 * Does nothing if firmware version is not matched
	 * Firmware range: Storage v0.49, v0.51+
	 * Storage only
	 * @param admin_pin 20 characters Admin PIN
	 * @return command processing error code
	 */
	NK_C_API int NK_set_unencrypted_read_only_admin(const char* admin_pin);

	/**
	 * Make unencrypted volume read-write.
	 * Device hides unencrypted volume for a second therefore make sure
	 * buffers are flushed before running.
	 * Does nothing if firmware version is not matched
	 * Firmware range: Storage v0.49, v0.51+
	 * Storage only
	 * @param admin_pin 20 characters Admin PIN
	 * @return command processing error code
	 */
	NK_C_API int NK_set_unencrypted_read_write_admin(const char* admin_pin);

	/**
	 * Make encrypted volume read-only.
	 * Device hides encrypted volume for a second therefore make sure
	 * buffers are flushed before running.
	 * Firmware range: v0.49 only, future (see firmware release notes)
	 * Storage only
	 * @param admin_pin 20 characters
	 * @return command processing error code
	 */
	NK_C_API int NK_set_encrypted_read_only(const char* admin_pin);

	/**
	 * Make encrypted volume read-write.
	 * Device hides encrypted volume for a second therefore make sure
	 * buffers are flushed before running.
	 * Firmware range: v0.49 only, future (see firmware release notes)
	 * Storage only
	 * @param admin_pin 20 characters
	 * @return command processing error code
	 */
	NK_C_API int NK_set_encrypted_read_write(const char* admin_pin);

	/**
	 * Exports device's firmware to unencrypted volume.
	 * Storage only
	 * @param admin_pin 20 characters
	 * @return command processing error code
	 */
	NK_C_API int NK_export_firmware(const char* admin_pin);

	/**
	 * Clear new SD card notification. It is set after factory reset.
	 * Storage only
	 * @param admin_pin 20 characters
	 * @return command processing error code
	 */
	NK_C_API int NK_clear_new_sd_card_warning(const char* admin_pin);

	/**
	 * Fill SD card with random data.
	 * Should be done on first stick initialization after creating keys.
	 * Storage only
	 * @param admin_pin 20 characters
	 * @return command processing error code
	 */
	NK_C_API int NK_fill_SD_card_with_random_data(const char* admin_pin);

	/**
	 * Change update password.
	 * Update password is used for entering update mode, where firmware
	 * could be uploaded using dfu-programmer or other means.
	 * Storage only
	 * @param current_update_password 20 characters
	 * @param new_update_password 20 characters
	 * @return command processing error code
	 */
	NK_C_API int NK_change_update_password(const char* current_update_password,
		const char* new_update_password);

	/**
	 * Enter update mode. Needs update password.
	 * When device is in update mode it no longer accepts any HID commands until
	 * firmware is launched (regardless of being updated or not).
	 * Smartcard (through CCID interface) and its all volumes are not visible as well.
	 * Its VID and PID are changed to factory-default (03eb:2ff1 Atmel Corp.)
	 * to be detected by flashing software. Result of this command can be reversed
	 * by using 'launch' command.
	 * For dfu-programmer it would be: 'dfu-programmer at32uc3a3256s launch'.
	 * Storage only
	 * @param update_password 20 characters
	 * @return command processing error code
	 */
	NK_C_API int NK_enable_firmware_update(const char* update_password);

	/**
	 * Get Storage stick status as string.
	 * Storage only
	 * @return string with devices attributes
	 */
	NK_C_API char* NK_get_status_storage_as_string();

	/**
	 * Get the Storage stick status and return the command processing
	 * error code.  If the code is zero, i. e. the command was successful,
	 * the storage status is written to the output pointer's target.
	 * The output pointer must not be null.
	 *
	 * @param out the output pointer for the storage status
	 * @return command processing error code
	 */
	NK_C_API int NK_get_status_storage(struct NK_storage_status* out);

	/**
	 * Get SD card usage attributes. Usable during hidden volumes creation.
	 * If the command was successful (return value 0), the usage data is
	 * written to the output pointer’s target.  The output pointer must
	 * not be null.
	 * Storage only
	 * @param out the output pointer for the usage data
	 * @return command processing error code
	 */
	NK_C_API int NK_get_SD_usage_data(struct NK_SD_usage_data* out);

	/**
	 * Get SD card usage attributes as string.
	 * Usable during hidden volumes creation.
	 * Storage only
	 * @return string with SD card usage attributes
	 */
	NK_C_API char* NK_get_SD_usage_data_as_string();

	/**
	 * Get progress value of current long operation.
	 * Storage only
	 * @return int in range 0-100 or -1 if device is not busy or -2 if an
	 *         error occured
	 */
	NK_C_API int NK_get_progress_bar_value();

/**
 * Returns a list of connected devices' id's, delimited by ';' character. Empty string is returned on no device found.
 * Each ID could consist of:
 * 1. SC_id:SD_id_p_path (about 40 bytes)
 * 2. path (about 10 bytes)
 * where 'path' is USB path (bus:num), 'SC_id' is smartcard ID, 'SD_id' is storage card ID and
 * '_p_' and ':' are field delimiters.
 * Case 2 (USB path only) is used, when the device cannot be asked about its status data (e.g. during a long operation,
 * like clearing SD card.
 * Internally connects to all available devices and creates a map between ids and connection objects.
 * Side effects: changes active device to last detected Storage device.
 * Storage only
 * @example Example of returned data: '00005d19:dacc2cb4_p_0001:0010:02;000037c7:4cf12445_p_0001:000f:02;0001:000c:02'
 * @return string delimited id's of connected devices
 */
	NK_C_API char* NK_list_devices_by_cpuID();

	/**
	 * Returns a linked list of all connected devices, or null if no devices
	 * are connected or an error occured.  The linked list must be freed by
	 * calling NK_free_device_info.
	 * @return a linked list of all connected devices
	 */
	NK_C_API struct NK_device_info* NK_list_devices();

	/**
	 * Free a linked list returned by NK_list_devices.
	 * @param the linked list to free or null
	 */
	NK_C_API void NK_free_device_info(struct NK_device_info* device_info);

/**
 * Connects to the device with given ID. ID's list could be created with NK_list_devices_by_cpuID.
 * Requires calling to NK_list_devices_by_cpuID first. Connecting to arbitrary ID/USB path is not handled.
 * On connection requests status from device and disconnects it / removes from map on connection failure.
 * Storage only
 * @param id Target device ID (example: '00005d19:dacc2cb4_p_0001:0010:02')
 * @return 1 on successful connection, 0 otherwise
 */
	NK_C_API int NK_connect_with_ID(const char* id);

	/**
	 * Connects to a device with the given path.  The path is a USB device
	 * path as returned by hidapi.
	 * @param path the device path
	 * @return 1 on successful connection, 0 otherwise
	 */
        NK_C_API int NK_connect_with_path(const char* path);

	/**
	 * Blink red and green LED alternatively and infinitely (until device is reconnected).
	 * @return command processing error code
	 */
	NK_C_API int NK_wink();


	/**
	 * Enable update mode on Nitrokey Pro.
	 * Supported from v0.11.
	 * @param update_password 20 bytes update password
   * @return command processing error code
	 */
	NK_C_API int NK_enable_firmware_update_pro(const char* update_password);

  /**
   * Change update-mode password on Nitrokey Pro.
   * Supported from v0.11.
   * @param current_firmware_password 20 bytes update password
   * @param new_firmware_password 20 bytes update password
   * @return command processing error code
   */
  NK_C_API int NK_change_firmware_password_pro(const char *current_firmware_password, const char *new_firmware_password);


// as in ReadSlot::ResponsePayload
struct ReadSlot_t {
  uint8_t slot_name[15];
  uint8_t _slot_config;
  uint8_t slot_token_id[13];
  uint64_t slot_counter;
};


NK_C_API int NK_read_HOTP_slot(const uint8_t slot_num, struct ReadSlot_t* out);

#ifdef __cplusplus
}
#endif

#endif //LIBNITROKEY_NK_C_API_H
