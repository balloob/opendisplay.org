/**
 * OpenDisplay manufacturer-specific data (MSD) — parse 16-byte payload matching firmware updatemsdata().
 * Use with raw bytes from BLE command 0x0044 (read MSD) or from advertising after company ID.
 * @see Firmware/src/display_service.cpp updatemsdata()
 */
(function (global) {
  'use strict';

  function hexBytes(u8) {
    if (!u8 || !u8.length) return '';
    return Array.from(u8)
      .map((b) => b.toString(16).padStart(2, '0').toUpperCase())
      .join(' ');
  }

  /**
   * Decode SHT40 3-byte compact block (dynamic bytes at indices 7–9 by default).
   */
  function decodeSht40Three(b0, b1, b2) {
    if ((b0 & 0xff) === 0xff && (b1 & 0xff) === 0xff && (b2 & 0xff) === 0xff) {
      return { valid: false, reason: 'invalid marker' };
    }
    const v = b0 | (b1 << 8) | (b2 << 16);
    const rhDeci = v & 0x3ff;
    const tu = (v >> 10) & 0x7ff;
    const tDeci = tu - 400;
    return {
      valid: true,
      tempC: tDeci / 10,
      rhPercent: rhDeci / 10,
      rhCenti: rhDeci * 10,
      tempCenti: tDeci * 10
    };
  }

  /**
   * Decode physical button byte (device_control.cpp: one byte at button_data_byte_index).
   * Bits 0–2: button_id (0–7), 3–6: press_count (0–15), 7: current_state (1 = pressed).
   */
  function decodeButtonByte(b) {
    const buttonId = b & 0x07;
    const pressCount = (b >> 3) & 0x0f;
    const pressed = ((b >> 7) & 0x01) === 1;
    return { buttonId, pressCount, pressed };
  }

  /**
   * Decode GT911-style 5-byte touch block at offset in dynamic region.
   */
  function decodeTouchFive(dyn, offset) {
    if (offset + 5 > dyn.length) return null;
    const b0 = dyn[offset];
    const low = b0 & 0x0f;
    const trackId = (b0 >> 4) & 0x0f;
    let contact = 'unknown';
    if (low === 0) contact = 'none';
    else if (low === 6) contact = 'released (last xy kept)';
    else if (low >= 1 && low <= 5) contact = low + ' contact(s) down';
    const x = dyn[offset + 1] | (dyn[offset + 2] << 8);
    const y = dyn[offset + 3] | (dyn[offset + 4] << 8);
    return { contact, trackId, x, y };
  }

  function resolveOptionalByteIndex(opts, key, defaultVal, maxInclusive) {
    if (!opts || !Object.prototype.hasOwnProperty.call(opts, key)) {
      return defaultVal;
    }
    const v = opts[key];
    if (v === null) return -1;
    const n = v | 0;
    if (n < 0 || n > maxInclusive) return -1;
    return n;
  }

  /** Packet IDs (decimal) match config wire format / config.yaml */
  var PID_SENSOR_DATA = 0x23;
  var PID_BINARY_INPUTS = 0x25;
  var PID_TOUCH_CONTROLLER = 0x28;
  var SENSOR_TYPE_SHT40 = 0x0004;
  var SENSOR_TYPE_BQ27220 = 0x0005;
  var TOUCH_IC_GT911 = 1;

  function decodeBq27220Packed(b) {
    if ((b & 0xff) === 0xff) {
      return { valid: false };
    }
    return {
      valid: true,
      percent: b & 0x7f,
      charging: (b & 0x80) !== 0
    };
  }

  /**
   * Build MSD decode options from bleLib.parseConfigBytes() result so only configured sensors are decoded.
   * @param {object|null} parsedConfig
   * @returns {{ buttonDataByteIndex: number|null, touchDataStartByte: number|null, sht40StartByte: number|null, bq27220StartByte: number|null }}
   */
  function extractMsdOptsFromParsedConfig(parsedConfig) {
    const out = {
      buttonDataByteIndex: null,
      touchDataStartByte: null,
      sht40StartByte: null,
      bq27220StartByte: null
    };
    if (!parsedConfig || !parsedConfig.packets || !parsedConfig.packets.length) {
      return out;
    }
    for (let i = 0; i < parsedConfig.packets.length; i++) {
      const p = parsedConfig.packets[i];
      const id = p.id;
      const data = p.data;
      if (!data || !data.length) continue;

      if (id === PID_SENSOR_DATA && data.length >= 6) {
        const sensorType = data[1] | (data[2] << 8);
        if (sensorType === SENSOR_TYPE_SHT40 && out.sht40StartByte === null) {
          let start = data[5];
          if (start === 0xff || start === undefined) start = 7;
          start = start & 0xff;
          // SHT40 reads 3 bytes (start..start+2) from the 11-byte dynamic region,
          // so start must be <= 8. Validate symmetrically with BQ27220's idx <= 10
          // check below; fall back to the default (7) rather than reporting an
          // index that parseMsd16 will never decode.
          if (start > 8) start = 7;
          out.sht40StartByte = start;
        }
        if (sensorType === SENSOR_TYPE_BQ27220 && out.bq27220StartByte === null) {
          const idx = data[5] & 0xff;
          if (idx <= 10 && idx !== 0xff) {
            out.bq27220StartByte = idx;
          }
        }
      }
      if (id === PID_BINARY_INPUTS && data.length > 15 && out.buttonDataByteIndex === null) {
        out.buttonDataByteIndex = data[15] & 0xff;
      }
      if (id === PID_TOUCH_CONTROLLER && data.length > 10 && out.touchDataStartByte === null) {
        const ic = data[1] | (data[2] << 8);
        if (ic === TOUCH_IC_GT911) {
          out.touchDataStartByte = data[10] & 0xff;
        }
      }
    }
    return out;
  }

  /**
   * @param {Uint8Array|number[]} msd16 — exactly 16 bytes (company LE + dynamic[11] + temp + batt + status)
   * @param {object} [opts] — optional layout from device config (use extractMsdOptsFromParsedConfig). If omitted, legacy decode shows button@0, touch@0, SHT40@7–9.
   * @param {number|null} [opts.buttonDataByteIndex] — null skips button line
   * @param {number|null} [opts.touchDataStartByte] — null skips touch line
   * @param {number|null} [opts.bq27220StartByte] — null skips BQ27220 SOC line; otherwise packed byte index in dynamic (0–10)
   * @returns {object} decoded fields and raw slices
   */
  function parseMsd16(msd16, opts) {
    const legacyMode = opts === undefined;
    // Normalize an explicit `null` opts so the direct `opts.*` reads below don't throw.
    if (!legacyMode) opts = opts || {};
    const u8 = msd16 instanceof Uint8Array ? msd16 : new Uint8Array(msd16);
    if (u8.length !== 16) {
      return { error: 'Expected 16 bytes, got ' + u8.length };
    }
    const companyId = u8[0] | (u8[1] << 8);
    const dynamic = u8.slice(2, 13);
    const tempByte = u8[13];
    const battLow = u8[14];
    const status = u8[15];
    const batt10mv = battLow | ((status & 0x01) << 8);
    const voltageV = batt10mv * 10 / 1000;
    const chipTempC = tempByte / 2 - 40;
    const rebootFlag = (status >> 1) & 1;
    const connectionRequested = (status >> 2) & 1;
    const mloopCounter = (status >> 4) & 0x0f;

    let buttonBlock = null;
    if (legacyMode) {
      const btnIdx = 0;
      buttonBlock = Object.assign({ index: btnIdx }, decodeButtonByte(dynamic[btnIdx]));
    } else {
      const btnIdx = resolveOptionalByteIndex(opts, 'buttonDataByteIndex', -1, 10);
      if (btnIdx >= 0) {
        buttonBlock = Object.assign({ index: btnIdx }, decodeButtonByte(dynamic[btnIdx]));
      }
    }

    let touchBlock = null;
    if (legacyMode) {
      touchBlock = decodeTouchFive(dynamic, 0);
      if (touchBlock) touchBlock.startByte = 0;
    } else {
      const touchStart = resolveOptionalByteIndex(opts, 'touchDataStartByte', -1, 6);
      if (touchStart >= 0) {
        touchBlock = decodeTouchFive(dynamic, touchStart);
        if (touchBlock) touchBlock.startByte = touchStart;
      }
    }

    let sht40At7 = null;
    let sht40StartByteUsed = 7;
    if (legacyMode) {
      sht40At7 = decodeSht40Three(dynamic[7], dynamic[8], dynamic[9]);
      sht40StartByteUsed = 7;
    } else if (opts.sht40StartByte != null) {
      const s = opts.sht40StartByte | 0;
      sht40StartByteUsed = s;
      if (s >= 0 && s + 2 < 11) {
        sht40At7 = decodeSht40Three(dynamic[s], dynamic[s + 1], dynamic[s + 2]);
      }
    }

    let bq27220StartByteUsed = null;
    let bq27220Packed = null;
    if (!legacyMode && opts.bq27220StartByte != null) {
      const bqIdx = opts.bq27220StartByte | 0;
      if (bqIdx >= 0 && bqIdx <= 10) {
        bq27220StartByteUsed = bqIdx;
        bq27220Packed = decodeBq27220Packed(dynamic[bqIdx]);
        bq27220Packed.index = bqIdx;
        if (!bq27220Packed.valid) {
          bq27220Packed.raw = dynamic[bqIdx] & 0xff;
        }
      }
    }

    return {
      companyId,
      companyIdHex: '0x' + companyId.toString(16).toUpperCase().padStart(4, '0'),
      dynamic11: dynamic,
      dynamic11Hex: hexBytes(dynamic),
      chipTempC,
      chipTempByte: tempByte,
      batteryVoltage10mV: batt10mv,
      batteryVoltageV: Math.round(voltageV * 1000) / 1000,
      statusByte: status,
      status: {
        rebootFlag,
        connectionRequested,
        mloopCounter
      },
      buttonBlock,
      touchBlock,
      // Deprecated alias of `touchBlock`. Despite the name it is NOT necessarily
      // decoded at offset 0: in config mode it reflects `touchDataStartByte`.
      // Prefer `touchBlock` (has `.startByte`); kept only for backward compatibility.
      touchBlockAt0: touchBlock,
      sht40At7: sht40At7,
      sht40StartByte: legacyMode ? 7 : opts.sht40StartByte != null ? sht40StartByteUsed : null,
      bq27220StartByte: legacyMode ? null : bq27220StartByteUsed,
      bq27220Packed,
      raw16Hex: hexBytes(u8)
    };
  }

  /**
   * Human-readable multi-line string for UI / logs.
   */
  function formatDecoded(d) {
    if (d.error) return 'Error: ' + d.error;
    const lines = [
      'Company ID: ' + d.companyIdHex + ' (' + d.companyId + ')',
      'Dynamic (11 B): ' + d.dynamic11Hex,
      'Chip temp: ' + (Number.isFinite(d.chipTempC) ? d.chipTempC.toFixed(2) + ' °C' : '—') + ' (byte 0x' + d.chipTempByte.toString(16).toUpperCase().padStart(2, '0') + ')',
      'Battery: ' + (d.batteryVoltage10mV > 0 ? d.batteryVoltageV + ' V (' + d.batteryVoltage10mV + ' × 10 mV)' : 'not configured / N/A'),
      'Status: reboot=' + d.status.rebootFlag + ', connReq=' + d.status.connectionRequested + ', mloop=' + d.status.mloopCounter
    ];
    if (d.bq27220StartByte != null) {
      const idx = d.bq27220StartByte;
      if (d.bq27220Packed && d.bq27220Packed.valid) {
        lines.push(
          'SOC @' +
            idx +
            ': ' +
            d.bq27220Packed.percent +
            ' %' +
            (d.bq27220Packed.charging ? ' (charging)' : '')
        );
      } else {
        const raw =
          d.bq27220Packed && d.bq27220Packed.raw != null
            ? '0x' + (d.bq27220Packed.raw & 0xff).toString(16).toUpperCase().padStart(2, '0')
            : '—';
        lines.push('SOC @' + idx + ': (no valid sample, raw ' + raw + ')');
      }
    }
    if (d.buttonBlock) {
      lines.push(
        'Button @' +
          d.buttonBlock.index +
          ': id=' +
          d.buttonBlock.buttonId +
          ', presses=' +
          d.buttonBlock.pressCount +
          ', ' +
          (d.buttonBlock.pressed ? 'pressed' : 'released')
      );
    }
    const tb = d.touchBlock || d.touchBlockAt0;
    if (tb) {
      const at = typeof tb.startByte === 'number' ? tb.startByte : 0;
      lines.push(
        'Touch @' +
          at +
          ': ' +
          tb.contact +
          ', track=' +
          tb.trackId +
          ', x=' +
          tb.x +
          ', y=' +
          tb.y
      );
    }
    if (d.sht40At7) {
      const a = typeof d.sht40StartByte === 'number' ? d.sht40StartByte : 7;
      const range = a + '–' + (a + 2);
      if (d.sht40At7.valid) {
        lines.push(
          'SHT40 @' +
            range +
            ': ' +
            d.sht40At7.tempC.toFixed(1) +
            ' °C, ' +
            d.sht40At7.rhPercent.toFixed(1) +
            ' % RH'
        );
      } else {
        lines.push('SHT40 @' + range + ': (no valid sample / disabled)');
      }
    }
    lines.push('Raw 16 B: ' + d.raw16Hex);
    return lines.join('\n');
  }

  /**
   * @param {{ readMsd: function(): Promise<Uint8Array> }} ble — OpenDisplay BLE instance
   * @returns {Promise<object>} same shape as parseMsd16()
   */
  async function readAndDecodeFromBle(ble, opts) {
    if (!ble || typeof ble.readMsd !== 'function') {
      throw new Error('BLE instance with readMsd() required');
    }
    const u8 = await ble.readMsd();
    return parseMsd16(u8, opts);
  }

  const api = {
    parseMsd16,
    formatDecoded,
    readAndDecodeFromBle,
    extractMsdOptsFromParsedConfig,
    decodeBq27220Packed,
    decodeButtonByte,
    decodeSht40Three,
    decodeTouchFive,
    hexBytes
  };

  global.OpenDisplayMsd = api;
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = api;
  }
})(typeof globalThis !== 'undefined' ? globalThis : typeof window !== 'undefined' ? window : this);
