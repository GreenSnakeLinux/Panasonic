package com.tv.panasonic;

import android.content.Context;
import android.content.ContextWrapper;
import android.content.SharedPreferences;
import android.os.AsyncTask;
import android.os.Handler;
import android.os.Looper;
import android.os.Message;

import android.preference.PreferenceManager;
import android.util.Base64;
import android.util.Log;
import android.widget.Toast;

import org.w3c.dom.Document;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.StringReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.SecureRandom;
import java.util.Formatter;
import java.util.Locale;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;


public class PanasonicTV extends ContextWrapper {

    private final static String DEFAULT_TV_IP = "192.168.1.10";
    private final static String DEFAULT_TV_PORT = "55000";
    private final static String CST_HTTP = "http://";
    private final static String KEY_TV_IP = "key_tv_ip";
    private final static String KEY_TV_PORT = "key_tv_port";
    private final static String XML_DATA_PARAM_FILE = "panasonic_param_header.xml";
    private final static String XML_ENC_DATA_FILE = "panasonic_encrypted_command.xml";
    private static final String TV_PANASONIC_SUFFIX = "/nrc/control_0";
    private static final String PANASONIC_BODY_ELEM = "body_elem";
    private static final String PANASONIC_ACTION_ELEM = "action_elem";
    private static final String PANASONIC_URN_ELEM = "urn_elem";
    private static final String PANASONIC_PARAMS_ELEM = "params_elem";
    private static final String PANASONIC_SESSION_ID_ELEM = "session_id_elem";
    private static final String PANASONIC_SEQ_NUM_ELEM = "seq_num_elem";

    private final static String KEY_APP_ID = "key_panasonic_app_id";
    private final static String KEY_ENC_KEY = "key_panasonic_enc_id";
    private final static String URL_CONTROL_NRC_DEF = "/nrc/sdd_0.xml";
    private final static String ENC_SESSION_ID_TAG = "X_GetEncryptSessionId";
    private final static String ENC_CMD_TAG = "X_EncryptedCommand";
    private final static String CHALLENGE_KEY_TAG = "X_ChallengeKey";
    private final static String ENC_RES_TAG = "X_EncResult";
    private final static String AUTH_RES_TAG = "X_AuthResult";
    private final static String DISPLAY_PIN_TAG = "X_DisplayPinCode";
    private final static String REQ_AUTH_TAG = "X_RequestAuth";
    private final static String SEND_KEY_TAG = "X_SendKey";
    private final static String LAUNCH_APP_TAG = "X_LaunchApp";
    private final static String DEVICE_NAME = "<X_DeviceName>My Remote</X_DeviceName>";
    private final static String URN_REMOTE_CONTROL = "panasonic-com:service:p00NetworkControl:1";

    private String myIP, myPort;
    private String m_app_id = "", m_encryption_key = "";
    private boolean m_is_encrypted = false;
    private int m_session_seq_num = 0;
    private String m_session_key = "", m_session_iv = "", m_session_hmac_key = "", m_session_id = "", m_challenge = "";

    public PanasonicTV(Context base) {
        super(base);
    }

    public void loadMainPreferences() {
        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(this);

        myIP = prefs.getString(KEY_TV_IP, DEFAULT_TV_IP);
        myPort = prefs.getString(KEY_TV_PORT, DEFAULT_TV_PORT);

        m_app_id = prefs.getString(KEY_APP_ID, "");
        m_encryption_key = prefs.getString(KEY_ENC_KEY, "");
    }

    public void saveIPPreference() {
        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(this);
        SharedPreferences.Editor editor = prefs.edit();
        editor.putString(KEY_TV_IP, getMyIP());
        editor.apply();
    }

    private void saveCredentials() {
        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(this);
        SharedPreferences.Editor editor = prefs.edit();

        editor.putString(KEY_APP_ID, m_app_id);
        editor.putString(KEY_ENC_KEY, m_encryption_key);

        editor.apply();
    }

    public void isEncrypttionNeeded() {
        isEncrypttionNeeded(getMyIP());
    }
    // Determine if the TV uses encryption or not
    private void isEncrypttionNeeded(String IP) {
        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(this);
        if (!prefs.contains(m_app_id)) {
            // Check if URL exist: URL_CONTROL_NRC_DEF
            new ExecuteURLDetectTV().executeOnExecutor(AsyncTask.THREAD_POOL_EXECUTOR,CST_HTTP + IP + ":" + getMyPort() + URL_CONTROL_NRC_DEF, ENC_SESSION_ID_TAG);
            // Then check returned data contain ENC_SESSION_ID_TAG
        } else {
            m_is_encrypted = true;
        }
    }

    private String getDecodeurURL(String IP) {
        return CST_HTTP + IP + ":" + getMyPort() + TV_PANASONIC_SUFFIX;
    }

    public String getMyIP() {return myIP;}

    public String getMyPort() {
        return myPort;
    }

    public void setMyIP(String lmyIP) {
         myIP = lmyIP;
    }
/*
    private void unitary_test() {
        if (BuildConfig.DEBUG) {
            String xml = "";

            // 1- CHALLENGE_KEY_TAG
            // 2- AUTH_RES_TAG
            // 3- ENC_RES_TAG

            String response_node = AUTH_RES_TAG; //CHALLENGE_KEY_TAG;
            String key = "´â»fk7.@ÜÕM3*\u009DÀÀ", iv = "99441d4bbfd1c894ccb22a233f3f62d5", hmac_key = "08c282c383c286781e183a640143337cc3a1c3af70c2b8003ec298640cc3862bc2a0c3ae6f4e46c29a076b";

            switch (response_node) {
                case CHALLENGE_KEY_TAG:
                    //mUQdS7/RyJTMsiojPz9i1Q==
                    //A2ZrfRk5oJarHc6IHL5BpQ== (NOK on Python)
                    xml = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n" +
                            "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">\n" +
                            " <s:Body>\n" +
                            "  <u:X_DisplayPinCodeResponse xmlns:u=\"urn:panasonic-com:service:p00NetworkControl:1\">\n" +
                            "   <X_ChallengeKey>mUQdS7/RyJTMsiojPz9i1Q==</X_ChallengeKey>\n" +
                            "  </u:X_DisplayPinCodeResponse>\n" +
                            " </s:Body>\n" +
                            "</s:Envelope>";
                    break;
                case ENC_RES_TAG:
                    xml = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n" +
                            "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">\n" +
                            " <s:Body>\n" +
                            "   <X_EncResult>11223344556677881122334455667788</X_EncResult>\n" +
                            " </s:Body>\n" +
                            "</s:Envelope>";
                    break;
                case AUTH_RES_TAG:
                    xml = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n" +
                            "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">\n" +
                            " <s:Body>\n" +
                            "  <u:X_RequestAuthResponse xmlns:u=\"urn:panasonic-com:service:p00NetworkControl:1\">\n" +
                            "   <X_AuthResult>ylQjLxBm3goWoCPJKSSduzj+GsCaTnr+a/wDQ0les4IFeVrkryPwmGU+5FJYE+Q8PYE0NoFb00e5dD5JB2N017eXRh1UM2PlwUcOgdLuw/vMALMzzofdLmZ9Si3jq4x5zGfLcl654+9IxZqbB6ND7k+fn/4se2sjB2KzGkYPQZk=</X_AuthResult>\n" +
                            "  </u:X_RequestAuthResponse>\n" +
                            " </s:Body>\n" +
                            "</s:Envelope>";
                    break;
                default:
                    break;
            }

            if (xml != null && !xml.isEmpty()) {
                String res = parseXMLResponse(xml, response_node);
                Log.d("TEST", "res = " + res);
                if (res != null && !res.isEmpty()) {
                    switch (response_node) {
                        case CHALLENGE_KEY_TAG:
                            //m_challenge = res;
                            byte[] challenge = Base64.decode(res, Base64.DEFAULT);
                            m_challenge = toHexString(challenge);
                            Log.d("TV", "Challenge: " + m_challenge);
                            displayPINKeyboard();
                            break;
                        case ENC_RES_TAG:
                            String enc_result_decrypted = "<X_Data>" + decrypt_soap_payload(res, m_session_key, m_session_iv, m_session_hmac_key) + "</X_Data>";
                            // Set session ID and begin sequence number at 1. We have to increment the sequence number upon each successful NRC command.
                            m_session_id = parseXMLResponse(enc_result_decrypted, "X_SessionId");
                            Log.d("TEST", "m_session_id = " + m_session_id);
                            m_session_seq_num = 1;
                            break;
                        case AUTH_RES_TAG:
                            String auth_result_decrypted = "<X_Data>" + decrypt_soap_payload(res, key, iv, hmac_key) + "</X_Data>"; // key, iv, hmac_key
                            m_app_id = parseXMLResponse(auth_result_decrypted, "X_ApplicationId");
                            m_encryption_key = parseXMLResponse(auth_result_decrypted, "X_Keyword");
                            Log.d("TEST", "m_app_id = " + m_app_id);
                            Log.d("TEST", "m_encryption_key = " + m_encryption_key);
                            if (m_app_id != null && m_encryption_key != null) {
                                saveCredentials();
                                // Derive AES & HMAC keys from X_Keyword
                                derive_session_keys();
                                // Request a session
                                request_session_id();
                            }
                            break;
                        default:
                            break;
                    }
                }
            }
        }
    }
*/
    public void process_pin_code(String pin) {
        authorize_pin_code(pin);
    }

    private void displayPINKeyboard() {
        Message msg = Message.obtain();
        MainActivity.mPinKeyboardHandler.sendMessage(msg);
    }

    private String toHexString(byte[] bytes) {
        Formatter formatter = new Formatter();

        for (byte b : bytes) {
            formatter.format("%02x", b);
        }

        return formatter.toString();
    }

    public String generateRandomPassword(int length) {
        StringBuilder sb = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            int c = new SecureRandom().nextInt(62);
            if (c <= 9) {
                sb.append(c);
            } else if (c < 36) {
                sb.append((char) ('a' + c - 10));
            } else {
                sb.append((char) ('A' + c - 36));
            }
        }
        return sb.toString();
    }

    private static byte[] hexToByteArray(String hex) {
        hex = hex.length()%2 != 0?"0"+hex:hex;

        byte[] b = new byte[hex.length() / 2];

        for (int i = 0; i < b.length; i++) {
            int index = i * 2;
            int v = Integer.parseInt(hex.substring(index, index + 2), 16);
            b[i] = (byte) v;
        }
        return b;
    }

    private static String hexToAscii(String s) {
        StringBuilder sb = new StringBuilder(s.length() / 2);
        for (int i = 0; i < s.length(); i+=2) {
            String hex = "" + s.charAt(i) + s.charAt(i+1);
            int ival = Integer.parseInt(hex, 16);
            sb.append((char) ival);
        }
        return sb.toString();
    }

    private String encrypt_soap_payload(String data, String key, String iv, String hmac_key) {
        try {
            // The encrypted payload must begin with a 16-byte header (12 random bytes, and 4 bytes for the payload length in big endian)
            // Note: the server does not appear to ever send back valid payload lengths in bytes 13-16, so I would assume these can also
            // be randomized by the client, but we'll set them anyway to be safe.
            String payload = generateRandomPassword(12);

            Log.d("TV", "Random: " + payload);

            Log.d("TV", "data: " + data);
            byte[] dataByte = data.getBytes();
            Log.d("TV", "data bytes: " + toHexString(dataByte));
            int len = 16 + dataByte.length;

            byte[] payloadByte = new byte[len];
            System.arraycopy(payload.getBytes(), 0, payloadByte, 0, 12);

            payloadByte[12] = (byte)(data.length() >> 24);
            payloadByte[13] = (byte)((data.length() >> 16) & 0xFF);
            payloadByte[14] = (byte)((data.length() >> 8) & 0xFF);
            payloadByte[15] = (byte)(data.length() & 0xFF);

            Log.d("TV", "Random + length: " + toHexString(payloadByte));

            System.arraycopy(dataByte, 0, payloadByte, 16, dataByte.length);

            // Initialize AES-CBC with key and IV
            byte[] secret = key.getBytes();
            byte[] iv_param = hexToByteArray(iv);

            Log.d("TV", "key: " + key);
            Log.d("TV", "iv: " + iv);
            Log.d("TV", "secret: " + toHexString(secret));
            Log.d("TV", "iv_param: " + toHexString(iv_param));

            Log.d("TV", "Message: " + toHexString(payloadByte));

            SecretKeySpec skeySpec = new SecretKeySpec(secret, "AES");
            IvParameterSpec ivSpec = new IvParameterSpec(iv_param);
            Cipher ecipher = Cipher.getInstance("AES/CBC/ZeroBytePadding");
            ecipher.init(Cipher.ENCRYPT_MODE, skeySpec, ivSpec);
            byte[] cipherBytes = ecipher.doFinal(payloadByte);
            Log.d("TV", "AES output: " + toHexString(cipherBytes));

            byte[] hmac_key_secret = hmac_key.getBytes();
            Log.d("TV", "HMAC secret: " + toHexString(hmac_key_secret));

            SecretKeySpec keySpec = new SecretKeySpec(hmac_key_secret, "HmacSHA256");
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(keySpec);
            byte[] rawHmac = mac.doFinal(cipherBytes);
            Log.d("TV", "HMAC output: " + toHexString(rawHmac));

            // Concat HMAC with AES-encrypted payload
            return Base64.encodeToString(hexToByteArray(toHexString(cipherBytes) + toHexString(rawHmac)), Base64.DEFAULT);
        } catch (Exception e) {
            e.printStackTrace();
            Log.e("TV", "Exception: " + e.getMessage());
        }

        return null;
    }

    private String decrypt_soap_payload(String data, String key, String iv, String hmac_key) {
        try {
            Log.d("TV", "decrypt_soap_payload:");
            Log.d("TV", "Data: " + data);
            Log.d("TV", "Key: " + key);
            Log.d("TV", "IV: " + iv);

            // Initialize AES-CBC with key and IV
            byte[] secret = key.getBytes();
            byte[] iv_param = hexToByteArray(iv);

            SecretKeySpec skeySpec = new SecretKeySpec(secret, "AES");
            IvParameterSpec ivSpec = new IvParameterSpec(iv_param);
            Cipher ecipher = Cipher.getInstance("AES/CBC/ZeroBytePadding");

            // Decrypt
            ecipher.init(Cipher.DECRYPT_MODE, skeySpec, ivSpec);
            byte[] raw = Base64.decode(data, Base64.DEFAULT);
            byte[] decrypted = ecipher.doFinal(raw);
            String decStr = toHexString(decrypted);
            Log.d("TV", "Data decrypted: " + decStr);
            decStr = decStr.substring(32);

            Log.d("TV", "Data decrypted-32: " + decStr);
            Log.d("TV", "Data decrypted ascii: " + hexToAscii(decStr));

            return hexToAscii(decStr);
        } catch (Exception e) {
            e.printStackTrace();
            Log.e("TV", "Exception: " + e.getMessage());
        }

        return null;
    }

    private void request_pin_code() {
        // First let's ask for a pin code and get a challenge key back
        new ExecuteSoapRequest().executeOnExecutor(AsyncTask.THREAD_POOL_EXECUTOR,getDecodeurURL(getMyIP()), "u", DISPLAY_PIN_TAG, URN_REMOTE_CONTROL, DEVICE_NAME, CHALLENGE_KEY_TAG);
    }

    private void derive_session_keys() {
        try {
            byte[] iv = Base64.decode(m_encryption_key, Base64.DEFAULT);
            m_session_iv = toHexString(iv);
            Log.d("TV", "Session IV: " + m_session_iv);

            // Initialise key character codes array
            byte[] key_vals = new byte[16];

            // Derive key from IV
            int i = 0;
            while (i < 16) {
                key_vals[i] = iv[i + 2];
                key_vals[i+1] = iv[i + 3];
                key_vals[i+2] = iv[i];
                key_vals[i+3] = iv[i + 1];
                i += 4;
            }

            // Convert our key character codes to bytes
            m_session_key = toHexString(key_vals);
            Log.d("TV", "Session key: " + m_session_key);

            // HMAC key for comms is just the IV repeated twice
            m_session_hmac_key = toHexString(iv) + toHexString(iv); //iv + iv;
            Log.d("TV", "Session HMAC key: " + m_session_hmac_key);
        } catch (Exception e) {
            e.printStackTrace();
            Log.e("TV", "Exception: " + e.getMessage());
        }
    }

    private void request_session_id() {
        // Thirdly, let's ask for a session. We'll need to use a valid session ID for encrypted NRC commands.

        // We need to send an encrypted version of X_ApplicationId
        String encinfo = encrypt_soap_payload(
                "<X_ApplicationId>" + m_app_id + "</X_ApplicationId>",
                m_session_key,
                m_session_iv,
                m_session_hmac_key);

        // Send the encrypted SOAP request along with plaintext X_ApplicationId
        String params = "<X_ApplicationId>" + m_app_id + "</X_ApplicationId>" +
                "<X_EncInfo>" + encinfo + "</X_EncInfo>";

        new ExecuteSoapRequest().executeOnExecutor(AsyncTask.THREAD_POOL_EXECUTOR,getDecodeurURL(getMyIP()), "u", ENC_SESSION_ID_TAG, URN_REMOTE_CONTROL, params, ENC_RES_TAG);
    }

    public void postToastMessage(final String message, final int duration) {
        Handler handler = new Handler(Looper.getMainLooper());
        handler.post(new Runnable() {
            @Override
            public void run() {
                Toast.makeText(PanasonicTV.this, message, duration).show();
            }
        });
    }

    private String parseXMLResponse(String xml, String nodeName) {
        if (xml.isEmpty()) {
            // test for debug
            if (BuildConfig.DEBUG) {
                //xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><response status=\"ok\"><sessionID>lo8mdn7bientr71b5kn1kote90</sessionID></response>";

                xml = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n" +
                        "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">\n" +
                        " <s:Body>\n" +
                        "  <s:Fault>\n" +
                        "   <faultcode>s:Client</faultcode>\n" +
                        "   <faultstring>UPnPError</faultstring>\n" +
                        "   <detail>\n" +
                        "    <UPnPError xmlns=\"urn:schemas-upnp-org:control-1-0\">\n" +
                        "     <errorCode>401</errorCode>\n" +
                        "     <errorDescription>Invalid action</errorDescription>\n" +
                        "    </UPnPError>\n" +
                        "   </detail>\n" +
                        "  </s:Fault>\n" +
                        " </s:Body>\n" +
                        "</s:Envelope>";
            }
        }

        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder;
        InputSource is;
        try {
            builder = factory.newDocumentBuilder();
            is = new InputSource(new StringReader(xml));
            Document doc = builder.parse(is);
            doc.getDocumentElement().normalize();
            NodeList list = doc.getElementsByTagName("errorDescription");
            if (list.getLength() > 0) {
                postToastMessage("Error: " + list.item(0).getTextContent(), Toast.LENGTH_LONG);
                Log.d("XML", list.item(0).getTextContent());
                return null;
            }
            list = doc.getElementsByTagName("errorCode");
            if (list.getLength() > 0) {
                String code = list.item(0).getTextContent();
                if (code.equals("600"))
                    postToastMessage("Invalid PIN code !", Toast.LENGTH_LONG);
                else
                    postToastMessage("Error code: " + code, Toast.LENGTH_LONG);
                Log.d("XML", code);
                return null;
            }

            list = doc.getElementsByTagName(nodeName);
            if (list.getLength() > 0) {
                Log.d("XML", list.item(0).getTextContent());
                return list.item(0).getTextContent();
            }

        } catch (Exception e) {
            e.printStackTrace();
            Log.e("XML", "IOException: " + e.getMessage());
            postToastMessage("IOException: " + e.getMessage(), Toast.LENGTH_LONG);
        }

        return null;
    }

    private void authorize_pin_code(String pincode) {
        try {
            Log.d("TV", "PIN: " + pincode);
            // Second, let's encrypt the pin code using the challenge key and send it back to authenticate
            // Derive key from IV
            String iv = m_challenge;
            Log.d("TV", "IV: " + iv);

            byte[] iv_vals = hexToByteArray(iv);
            char[] key = new char[16];
            int i = 0;
            while (i < 16) {
                key[i] = (char) (~(int) (iv_vals[i + 3]) & 0xFF);
                key[i+1] = (char) (~(int) (iv_vals[i + 2]) & 0xFF);
                key[i+2] = (char) (~(int) (iv_vals[i + 1]) & 0xFF);
                key[i+3] = (char) (~(int) (iv_vals[i]) & 0xFF);
                i += 4;
            }
            Log.d("TV", "Key: " + String.valueOf(key));

            // Derive HMAC key from IV & HMAC key mask (taken from libtvconnect.so)
            char[] hmac_key_mask_vals = {0x15, 0xC9, 0x5A, 0xC2, 0xB0, 0x8A, 0xA7, 0xEB, 0x4E, 0x22, 0x8F, 0x81, 0x1E, 0x34, 0xD0, 0x4F, 0xA5, 0x4B, 0xA7, 0xDC, 0xAC, 0x98, 0x79, 0xFA, 0x8A, 0xCD, 0xA3, 0xFC, 0x24, 0x4F, 0x38, 0x54};
            char[] hmac_key = new char[32];
            i = 0;
            while (i < 32) {
                hmac_key[i] = (char) ((int)hmac_key_mask_vals[i]&0xFF ^ (int)(iv_vals[(i + 2) & 0xF])&0xFF);
                hmac_key[i+1] = (char) ((int)hmac_key_mask_vals[i + 1]&0xFF ^ (int)(iv_vals[(i + 3) & 0xF])&0xFF);
                hmac_key[i+2] = (char) ((int)hmac_key_mask_vals[i + 2]&0xFF ^ (int)(iv_vals[i & 0xF])&0xFF);
                hmac_key[i+3] = (char) ((int)hmac_key_mask_vals[i + 3]&0xFF ^ (int)(iv_vals[(i + 1) & 0xF])&0xFF);
                i += 4;
            }
            Log.d("TV", "HMAC Key: " + String.valueOf(hmac_key));

            // Encrypt X_PinCode argument and send it within an X_AuthInfo tag
            String params = "<X_AuthInfo>" + encrypt_soap_payload("<X_PinCode>" + pincode + "</X_PinCode>", String.valueOf(key), iv, String.valueOf(hmac_key)) + "</X_AuthInfo>";

            new ExecuteSoapRequest().executeOnExecutor(AsyncTask.THREAD_POOL_EXECUTOR,getDecodeurURL(getMyIP()), "u", REQ_AUTH_TAG, URN_REMOTE_CONTROL, params, AUTH_RES_TAG, String.valueOf(key), iv, String.valueOf(hmac_key));
        } catch (Exception e) {
            e.printStackTrace();
            postToastMessage("Exception: " + e.getMessage(), Toast.LENGTH_LONG);
        }
    }

    private void isFirstLaunch() {
        if(m_session_key.isEmpty()) {
            SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(this);
            m_is_encrypted = prefs.contains(m_app_id);
            if(m_is_encrypted) {
                derive_session_keys();
                request_session_id();
            }
        }
    }

    public void send_key(String key) {
        // Send a key command to the TV.
        isFirstLaunch();
        String params = "<X_KeyEvent>" + key + "</X_KeyEvent>";
        new ExecuteSoapRequest().executeOnExecutor(AsyncTask.THREAD_POOL_EXECUTOR,getDecodeurURL(getMyIP()), "m", SEND_KEY_TAG, URN_REMOTE_CONTROL, params);
    }

    public void launch_app(String app) {
        // Launch an app.
        isFirstLaunch();
        String params = "<X_AppType>vc_app</X_AppType><X_LaunchKeyword>";
        if( app.length() != 16)
            params += "resource_id=" + app + "</X_LaunchKeyword>";
        else
            params += "product_id=" + app + "</X_LaunchKeyword>";

        new ExecuteSoapRequest().executeOnExecutor(AsyncTask.THREAD_POOL_EXECUTOR,getDecodeurURL(getMyIP()), "m", LAUNCH_APP_TAG, URN_REMOTE_CONTROL, params);
    }

    // Converting InputStream to String
    public String readStream(InputStream in) {
        BufferedReader reader = null;
        StringBuilder response = new StringBuilder();
        try {
            reader = new BufferedReader(new InputStreamReader(in));
            String line;
            while ((line = reader.readLine()) != null) {
                response.append(line);
            }
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            if (reader != null) {
                try {
                    reader.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
        return response.toString();
    }

    public class ExecuteSoapRequest extends AsyncTask<String, Integer ,String> {

        private String server_response;
        private String str_url;
        private String str_ip_port;
        private String body_elem;
        private String action_elem;
        private String urn_elem;
        private String params_elem;
        private String response_node="";

        ExecuteSoapRequest() {
            super();
        }

        @Override
        protected void onProgressUpdate(Integer... progress) {
            if(progress[0]==0)
                Toast.makeText(PanasonicTV.this, server_response, Toast.LENGTH_LONG).show();
            else
                Toast.makeText(PanasonicTV.this, "Response code = " + progress[1], Toast.LENGTH_LONG).show();
        }

        @Override
        protected String doInBackground(String... strings) {
            URL url;
            HttpURLConnection urlConnection = null;
            str_url = strings[0];
            body_elem = strings[1];
            action_elem = strings[2];
            urn_elem = strings[3];
            params_elem = strings[4];
            if( strings.length > 5)
                response_node = strings[5];

            try {
                Log.d("TV", "URL: " + str_url);

                url = new URL(str_url);
                Log.i("TV", url.toString());

                str_ip_port = str_url.replace(CST_HTTP,"");
                str_ip_port = str_ip_port.replace(TV_PANASONIC_SUFFIX,"");

                // Encapsulate URN_REMOTE_CONTROL command in an X_EncryptedCommand if we're using encryption
                boolean is_encrypted = false;
                if(urn_elem.equals(URN_REMOTE_CONTROL) && !action_elem.equals(ENC_SESSION_ID_TAG) && !action_elem.equals(DISPLAY_PIN_TAG) && !action_elem.equals(REQ_AUTH_TAG) ) {
                    if(!m_session_key.isEmpty() && !m_session_iv.isEmpty() && !m_session_hmac_key.isEmpty() && !m_session_id.isEmpty()) {
                        is_encrypted = true;
                        m_session_seq_num += 1;

                        String enc_data="";
                        try {
                            InputStream stream;
                            stream = getAssets().open(XML_ENC_DATA_FILE);
                            int enc_size = stream.available();
                            byte[] buffer = new byte[enc_size];
                            stream.read(buffer);
                            stream.close();
                            enc_data = new String(buffer);
                            enc_data = enc_data.replace(PANASONIC_SESSION_ID_ELEM, m_session_id);
                            enc_data = enc_data.replace(PANASONIC_SEQ_NUM_ELEM, String.format(Locale.getDefault(),"%08d", m_session_seq_num));
                            enc_data = enc_data.replace(PANASONIC_ACTION_ELEM, action_elem);
                            enc_data = enc_data.replace(PANASONIC_URN_ELEM, urn_elem);
                            enc_data = enc_data.replace(PANASONIC_PARAMS_ELEM, params_elem);
                            enc_data = enc_data.replace(PANASONIC_BODY_ELEM, body_elem);
                            Log.d("TV", "Enc data: " + enc_data);
                        } catch (Exception e) {
                            server_response = e.getMessage();
                            Log.e("TV", "Exception: " + server_response);
                            e.printStackTrace();
                            publishProgress(0);
                        }

                        enc_data = encrypt_soap_payload(enc_data, m_session_key, m_session_iv, m_session_hmac_key);

                        action_elem = ENC_CMD_TAG;
                        params_elem = "<X_ApplicationId>" + m_app_id + "</X_ApplicationId>" +
                            "<X_EncInfo>"+ enc_data + "</X_EncInfo>";
                        body_elem = "u";

                    }
                }

                urlConnection = (HttpURLConnection) url.openConnection();
                urlConnection.setRequestMethod("POST");
                urlConnection.setDoOutput(true); // Same as urlConnection.setRequestMethod("POST");
                urlConnection.setConnectTimeout(3000);
                urlConnection.setReadTimeout(5000);

                int size = 0;
                String data="";
                try {
                    InputStream stream;
                    stream = getAssets().open(XML_DATA_PARAM_FILE);
                    size = stream.available();
                    byte[] buffer = new byte[size];
                    stream.read(buffer);
                    stream.close();
                    data = new String(buffer);
                    data = data.replace(PANASONIC_BODY_ELEM, body_elem);
                    data = data.replace(PANASONIC_ACTION_ELEM, action_elem);
                    data = data.replace(PANASONIC_URN_ELEM, urn_elem);
                    data = data.replace(PANASONIC_PARAMS_ELEM, params_elem);
                    size = data.length();
                    Log.d("TV", "Data: " + data);
                } catch (Exception e) {
                    server_response = e.getMessage();
                    Log.e("TV", "Exception: " + server_response);
                    e.printStackTrace();
                    publishProgress(0);
                }

                Log.d("TV", "Host: " + str_ip_port);
                urlConnection.setRequestProperty("Host", str_ip_port);
                //urlConnection.setRequestProperty("USER-AGENT", "Panasonic Android VR-CP UPnP/2.0");
                urlConnection.setRequestProperty("Content-Length", Integer.toString(size));
                urlConnection.setRequestProperty("Content-Type", "text/xml; charset=utf-8");
                urlConnection.setRequestProperty("SOAPAction", "\"urn:" + urn_elem + "#" + action_elem + "\"");

                urlConnection.setChunkedStreamingMode(0);
                OutputStream send = urlConnection.getOutputStream();
                BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(send, "UTF-8")); // StandardCharsets.UTF_8

                Log.d("TV", "Data = " + data);
                writer.write(data);

                writer.flush();
                writer.close();
                send.close();

                int responseCode = urlConnection.getResponseCode();

                if(responseCode == HttpURLConnection.HTTP_OK){
                    server_response = readStream(urlConnection.getInputStream());

                    Log.v("TV", server_response);

                    if(is_encrypted) {
                        String enc_result = parseXMLResponse(server_response, ENC_RES_TAG);
                        if(enc_result!=null)
                            server_response = decrypt_soap_payload(enc_result, m_session_key, m_session_iv, m_session_hmac_key);
                    }

                    if(response_node!=null && !response_node.isEmpty() && server_response!=null) {
                        String res = parseXMLResponse(server_response, response_node);
                        if(res!=null && !res.isEmpty()) {
                            switch (response_node) {
                                case CHALLENGE_KEY_TAG: // request_pin_code
                                    byte[] challenge = Base64.decode(res, Base64.DEFAULT);
                                    m_challenge = toHexString(challenge);
                                    Log.d("TV", "Challenge: " + m_challenge);
                                    displayPINKeyboard();
                                    break;
                                case ENC_RES_TAG: // request_session_id
                                    String enc_result_decrypted = "<X_Data>" + decrypt_soap_payload(res, m_session_key, m_session_iv, m_session_hmac_key) + "</X_Data>";
                                    // Set session ID and begin sequence number at 1. We have to increment the sequence number upon each successful NRC command.
                                    m_session_id = parseXMLResponse(enc_result_decrypted, "X_SessionId");
                                    m_session_seq_num = 1;
                                    break;
                                case AUTH_RES_TAG: // authorize_pin_code
                                    String auth_result_decrypted = "<X_Data>" + decrypt_soap_payload(res, strings[6], strings[7], strings[8]) + "</X_Data>"; // key, iv, hmac_key
                                    m_app_id = parseXMLResponse(auth_result_decrypted, "X_ApplicationId");
                                    Log.d("TV", "App_id: " + m_app_id);
                                    m_encryption_key = parseXMLResponse(auth_result_decrypted, "X_Keyword");
                                    Log.d("TV", "Encryption_key: " + m_encryption_key);
                                    if(m_app_id!= null && m_encryption_key!=null) {
                                        saveCredentials();
                                        // Derive AES & HMAC keys from X_Keyword
                                        derive_session_keys();
                                        // Request a session
                                        request_session_id();
                                    }
                                    break;
                                default:
                                    break;
                            }
                        }
                    }

                    return null;

                } else {
                    publishProgress(1, responseCode);
                    Log.d("TV", "Response code = " + responseCode);

                    if(m_session_seq_num > 0)
                        m_session_seq_num -= 1;

                    // In case of HttpURLConnection.HTTP_SERVER_ERROR (500)
                    parseXMLResponse(server_response, "");
                    return null;
                }

            } catch (java.net.SocketTimeoutException e) {
                Log.d("TV", "SocketTimeoutException = " + e.getMessage());
                return "SocketTimeoutException = " + e.getMessage();
            } catch (java.io.IOException e) {
                Log.d("TV", "IOException = " + e.getMessage());
                return "IOException = " + e.getMessage();
            } catch (Exception e) {
                Log.d("TV", "Exception = " + e.getMessage());
                return "Exception = " + e.getMessage();
            }
            finally {
                if(urlConnection != null)
                    urlConnection.disconnect();
            }
        }

        @Override
        protected void onPostExecute(String s) {
            super.onPostExecute(s);

            Log.d("Response", "" + server_response);
            Log.d("s", "" + s);

            /*if(android.os.Debug.isDebuggerConnected())
                android.os.Debug.waitForDebugger();*/

            if(s!=null && !s.isEmpty())
                postToastMessage(s, Toast.LENGTH_LONG);
        }
    }

    public class ExecuteURLDetectTV extends AsyncTask<String, Integer ,String> {

        private String server_response;
        private String str_url;
        private String nodeName;

        ExecuteURLDetectTV() {
            super();
        }

        @Override
        protected String doInBackground(String... strings) {
            URL url;
            HttpURLConnection urlConnection = null;
            str_url = strings[0];
            nodeName = strings[1];

	        /*if(android.os.Debug.isDebuggerConnected())
		        android.os.Debug.waitForDebugger();*/

            try {
                url = new URL(str_url);
                Log.i("TV", url.toString());

                urlConnection = (HttpURLConnection) url.openConnection();
                urlConnection.setConnectTimeout(3000);
                urlConnection.setReadTimeout(5000);

                int responseCode = urlConnection.getResponseCode();

                if(responseCode == HttpURLConnection.HTTP_OK){
                    server_response = readStream(urlConnection.getInputStream());

                    Log.v("TV", server_response);

                    String res = parseXMLResponse(server_response, nodeName);
                    if(res!=null)
                        m_is_encrypted = !res.isEmpty();
                    else
                        m_is_encrypted = false;

                    if(m_is_encrypted)
                        request_pin_code();

                    return null;
                }
                else {
                    m_is_encrypted = false;
                    throw new Exception("Response code = " + responseCode);
                }
            } catch (java.net.SocketTimeoutException e) {
                m_is_encrypted = false;
                return "SocketTimeoutException: " + e.getMessage();
            } catch (java.io.IOException e) {
                m_is_encrypted = false;
                return "IOException: " + e.getMessage();
            } catch (Exception e) {
                m_is_encrypted = false;
                return "Exception: " + e.getMessage();
            }
            finally {
                if(urlConnection != null)
                    urlConnection.disconnect();
            }
        }

        @Override
        protected void onPostExecute(String s) {
            super.onPostExecute(s);

            Log.d("Response", "" + server_response);
            Log.d("s", "" + s);

			/*if(android.os.Debug.isDebuggerConnected())
				android.os.Debug.waitForDebugger();*/

            if(s!=null && !s.isEmpty())
                postToastMessage(s, Toast.LENGTH_LONG);
        }
    }
}