package com.github.dazoe.android.ed25519bench;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Random;

import com.github.dazoe.android.Ed25519;
import android.os.AsyncTask;
import android.os.Bundle;
import android.app.Activity;
import android.app.ProgressDialog;
import android.util.Base64;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;

public class MainActivity extends Activity implements OnClickListener {
	EditText messageEditText;
	EditText seedEditText;
	EditText loopCountEditText;
	TextView outputTextView;

	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.activity_main);
		messageEditText = (EditText)findViewById(R.id.message);
		seedEditText = (EditText)findViewById(R.id.seed);
		loopCountEditText = (EditText)findViewById(R.id.loopCount);
		outputTextView = (TextView)findViewById(R.id.output);
		
		Button btn = (Button)findViewById(R.id.run_button);
		btn.setOnClickListener(this);
	}

	@Override
	public void onClick(View v) {
		final ProgressDialog dialog = new ProgressDialog(this);
		dialog.setProgressStyle(ProgressDialog.STYLE_HORIZONTAL);
		dialog.setTitle("Running...");
		dialog.setMax(100);
		dialog.show();
		final byte[] message = messageEditText.getText().toString().getBytes();
		if (seedEditText.length() <= 0) {
			Random rand = new Random();
			byte[] buf = new byte[10];
			rand.nextBytes(buf);
			seedEditText.setText(Base64.encodeToString(buf, Base64.URL_SAFE | Base64.NO_PADDING));
		}
		final byte[] seed = seedEditText.getText().toString().getBytes();
		final int loopCount = Integer.parseInt(loopCountEditText.getText().toString());

		AsyncTask<Void, Integer, String> task = new AsyncTask<Void, Integer, String>() {
			@Override
			protected String doInBackground(Void... params) {
				MessageDigest sha256;
				try {
					sha256 = MessageDigest.getInstance("SHA-256");
				} catch (NoSuchAlgorithmException e) {
					e.printStackTrace();
					return "Error";
				}
				byte[] privateKey = null, signature = null, publicKey = null;
				long stopwatch = System.currentTimeMillis();
				long verify_time = 0;
				int last_percent = 0;
				int percent;
				try {
					for (int i = 0; i < loopCount; i++) {
						privateKey = sha256.digest(seed);
						signature = Ed25519.Sign(message, privateKey);
						publicKey = Ed25519.PublicKeyFromPrivateKey(privateKey);
						verify_time -= System.currentTimeMillis();
						if (Ed25519.Verify(message, signature, publicKey) != 0) {
							throw new Exception("Verify failed during loops?");
						}
						verify_time += System.currentTimeMillis();
						percent = (i * 100 / loopCount);
						if (percent > last_percent) {
							publishProgress(percent);
							last_percent = percent;
						}
					}

					stopwatch = System.currentTimeMillis() - stopwatch;
					StringBuilder sb = new StringBuilder();
					sb.append("PrivateKey: ").append(Base64.encodeToString(privateKey, Base64.URL_SAFE | Base64.NO_PADDING))
					.append("\nPublicKey: ").append(Base64.encodeToString(publicKey, Base64.URL_SAFE | Base64.NO_PADDING))
					.append("\nSignature: ").append(Base64.encodeToString(signature, Base64.URL_SAFE | Base64.NO_PADDING))
					.append("\n\nTime Verifying: ").append(verify_time).append("ms")
					.append(" Avg: ").append((double)verify_time / loopCount).append("ms\n")
					.append("Total time: ").append(stopwatch).append("ms")
					.append(" Avg: ").append((double)stopwatch / loopCount).append("ms\n");
					return sb.toString();
				} catch (Exception e) {
					e.printStackTrace();
					return e.getMessage();
				}
			}
			@Override
			protected void onProgressUpdate(Integer... values) {
				dialog.setProgress(values[0]);
				super.onProgressUpdate(values);
			}
			@Override
			protected void onPostExecute(String result) {
				outputTextView.setText(result);
				dialog.dismiss();
				super.onPostExecute(result);
			}
		};
		task.execute();
	}
}
