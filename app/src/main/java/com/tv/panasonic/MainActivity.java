package com.tv.panasonic;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;

import android.content.Context;
import android.os.Bundle;
import android.os.Handler;
import android.os.Message;
import android.text.Editable;
import android.text.TextWatcher;
import android.util.Log;
import android.view.KeyEvent;
import android.view.LayoutInflater;
import android.view.View;
import android.view.WindowManager;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.EditText;
import android.widget.Spinner;
import android.widget.Toast;

public class MainActivity extends AppCompatActivity {

    private static PanasonicTV m_tv;
    private static String m_current_key;
    private static boolean m_firstLaunch = true;
    public static Handler mPinKeyboardHandler;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        m_tv = new PanasonicTV(this);
        m_tv.loadMainPreferences();

        EditText ip_view = findViewById(R.id.editText);
        ip_view.setText(m_tv.getMyIP());
        ip_view.addTextChangedListener(new TextWatcher() {
            @Override
            public void afterTextChanged(Editable s) {
                m_tv.setMyIP(s.toString());
                m_tv.saveIPPreference();
            }

            @Override
            public void beforeTextChanged(CharSequence s, int start,
                                          int count, int after) {
            }

            @Override
            public void onTextChanged(CharSequence s, int start,
                                      int before, int count) {
            }
        });

        mPinKeyboardHandler = new Handler(new Handler.Callback() {
            @Override
            public boolean handleMessage(@NonNull Message msg) {
                displayPINKeyboard();
                return true;
            }
        });

        Spinner staticSpinner = findViewById(R.id.spinner);
        ArrayAdapter<CharSequence> staticAdapter = ArrayAdapter
                .createFromResource(this, R.array.action_array,
                        android.R.layout.simple_spinner_item);
        staticAdapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        staticSpinner.setAdapter(staticAdapter);
        staticSpinner.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
            @Override
            public void onItemSelected(AdapterView<?> parent, View view,
                                       int position, long id) {
                Log.d("item", (String) parent.getItemAtPosition(position));
                m_current_key = (String) parent.getItemAtPosition(position);
                m_firstLaunch = true;
            }

            @Override
            public void onNothingSelected(AdapterView<?> parent) {
            }
        });
    }

    private void displayPINKeyboard() {
        try {
            LayoutInflater inflater = (LayoutInflater) getSystemService(Context.LAYOUT_INFLATER_SERVICE);
            if (inflater != null) {
                View dialogView = inflater.inflate(R.layout.pin_picker_dialog, null);

                androidx.appcompat.app.AlertDialog.Builder builder = new androidx.appcompat.app.AlertDialog.Builder(this);

                final androidx.appcompat.app.AlertDialog keyboardDialog;

                builder.setTitle("Enter TV PIN code");
                builder.setCancelable(false);

                builder.setView(dialogView);

                keyboardDialog = builder.create();
                if (keyboardDialog.getWindow() != null)
                    keyboardDialog.getWindow().setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_STATE_VISIBLE);

                EditText edtKeyboard = dialogView.findViewById(R.id.edtPinKeyboardText);
                edtKeyboard.requestFocus();

                edtKeyboard.setOnKeyListener(new View.OnKeyListener() {
                    @Override
                    public boolean onKey(View v, int keyCode, KeyEvent event) {
                        EditText view = (EditText) v;
                        if (event.getAction() != KeyEvent.ACTION_DOWN)
                            return false;
                        if (keyCode == KeyEvent.KEYCODE_ENTER) {
                            keyboardDialog.dismiss();
                            m_tv.process_pin_code(view.getText().toString());
                            return true;
                        }
                        return false;
                    }
                });

                keyboardDialog.show();
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void onSendButtonClick(View view) {
        if(m_current_key!=null && !m_current_key.isEmpty()) {
            Log.d("TV", "Send key: " + m_current_key);

            if(m_firstLaunch) {
                Toast.makeText(this, "Please, detect TV first", Toast.LENGTH_SHORT).show();
            } else {
                m_tv.send_key(m_current_key);
            }
        }
        else
            Toast.makeText(this, "Please, select an action first", Toast.LENGTH_SHORT).show();
    }

    public void onDetectButtonClick(View view) {
        m_tv.isEncrypttionNeeded();
        m_firstLaunch = false;
    }
}
