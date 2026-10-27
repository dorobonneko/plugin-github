package moe;
import android.webkit.WebResourceRequest;
import android.webkit.WebResourceResponse;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.SecureRandom;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.security.cert.X509Certificate;
import java.io.ByteArrayOutputStream;
import org.json.JSONObject;
import java.io.InputStream;
import org.json.JSONException;
import java.io.ByteArrayInputStream;
import java.security.cert.CertificateException;
import java.util.Iterator;
import java.util.Map;
import org.json.JSONArray;
import java.io.OutputStream;
import java.util.HashMap;
import android.app.*;
import android.content.*;
import android.os.*;
import java.util.*;
public class Hook implements IHook {
	private HookCallback callback;
	private Context ctx;
	private String[] releases = new String[]{null, null, "releases", "download"};
	private String[] zip = new String[]{null, null, null, "refs"};
	//private String[] code=new String[]{null,null,"raw","refs","heads"};
	public Hook(Context ctx) {
		this.ctx = ctx;
	}

	@Override
	public void onCreate(HookCallback callback) {
		this.callback = callback;

	}

	@Override
	public int getHookType(WebResourceRequest webResourceRequest) {
		switch (webResourceRequest.getUrl().getHost()) {
			case "codeload.github.com" :
			case "raw.githubusercontent.com" :
			case "release-assets.githubusercontent.com" :
				return 1;
			case "github.com" :
				List<String> paths = webResourceRequest.getUrl().getPathSegments();

				if (match(paths, releases, 2) || match(paths, zip, 3))
					return 1;
			case "sourceforge.net" :
				if (webResourceRequest.getUrl().getLastPathSegment().equals("download"))
					return 2;
		}
		return 0;
		//return "github.com".equals(webResourceRequest.getUrl().getHost());
	}
	private boolean match(List<String> paths, String[] releases, int offset) {
		if (paths.size() > releases.length) {
			for (int i = offset; i < releases.length; i++) {
				if (!releases[i].equals(paths.get(i)))
					return false;
			}
			return true;
		}
		return false;
	}
	@Override
	public String[] getWhiteList() {
		// TODO: Implement this method
		return new String[]{"github.com", "sourceforge.net"};
	}



	public WebResourceResponse hook(WebResourceRequest request, int type) {
		switch (type) {
			case 1 :
				callback.download("https://v4.gh-proxy.org/" + request.getUrl().toString(), request.getUrl().getLastPathSegment(), request.getRequestHeaders());
				break;
			case 2 :
				List<String> paths=request.getUrl().getPathSegments();
				
				callback.download("https://v4.gh-proxy.org/sourceforge/" + request.getUrl().toString(), paths.get(paths.size()-2), request.getRequestHeaders());

				break;
		}
		Map<String, String> m = new HashMap<>();
		//m.put("Location", "https://v4.gh-proxy.org/" + request.getUrl().toString());
		WebResourceResponse res = new WebResourceResponse("text/plain", "utf-8", 200, "No Content", m, new ByteArrayInputStream("已触发下载加速".getBytes()));
		return res;
	}
}



