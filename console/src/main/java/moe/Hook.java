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
	private String[] releases=new String[]{null,null,"releases","download"};
	private String[] zip=new String[]{null,null,null,"refs"};
	//private String[] code=new String[]{null,null,"raw","refs","heads"};
	public Hook(Context ctx){
		this.ctx=ctx;
	}

	@Override
	public void onCreate(HookCallback callback) {
		this.callback = callback;
		
	}

	@Override
	public boolean canHook(WebResourceRequest webResourceRequest)
	{
		switch(webResourceRequest.getUrl().getHost()){
			case "codeload.github.com":
			case "raw.githubusercontent.com":
				case "release-assets.githubusercontent.com":
			return true;
			case "github.com":
		List<String> paths=webResourceRequest.getUrl().getPathSegments();
		
		return match(paths,releases,2)||match(paths,zip,3);
		}
		return false;
		//return "github.com".equals(webResourceRequest.getUrl().getHost());
	}
	private boolean match(List<String> paths,String[] releases,int offset){
		if(paths.size()>releases.length){
			for( int i = offset; i < releases.length; i++) {
				if(!releases[i].equals(paths.get(i)))
					return false;
			}
			return true;
		}
		return false;
	}
	@Override
	public String[] getWhiteList()
	{
		// TODO: Implement this method
		return new String[]{"github.com"};
	}



	public WebResourceResponse hook(WebResourceRequest request) {
		callback.download("https://v4.gh-proxy.org/"+request.getUrl().toString(),request.getUrl().getLastPathSegment(),request.getRequestHeaders());
		Map<String,String> m=new HashMap<>();
		m.put("Location","https://v4.gh-proxy.org/"+request.getUrl().toString());
		WebResourceResponse res=new WebResourceResponse("text/plain","utf-8",200,"No Content",m,new ByteArrayInputStream("已触发下载加速".getBytes()));
		return res;
		}
}

