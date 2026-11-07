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
import android.net.Uri;
import java.nio.charset.StandardCharsets;
public class Hook implements IHook {

    private static final String PROXY_BASE = "https://v4.gh-proxy.org/";
    private static final String SOURCEFORGE_PREFIX = PROXY_BASE + "sourceforge/";

    private static final int TYPE_NONE        = 0;
    private static final int TYPE_GITHUB      = 1;
    private static final int TYPE_SOURCEFORGE = 2;

    /** github.com 上 releases 下载路径特征：/releases/download/... */
    private static final String[] GITHUB_RELEASES_PATH = {null, null, "releases", "download"};
    /** github.com 上归档 zip 路径特征：/archive/refs/... */
    private static final String[] GITHUB_ZIP_PATH      = {null, null, null, "refs"};

    private HookCallback callback;
    private final Context ctx;

    public Hook(Context ctx) {
        this.ctx = ctx;
    }

    @Override
    public void onCreate(HookCallback callback) {
        this.callback = callback;
    }

    @Override
    public int getHookType(HookRequest request) {
        Uri url = request.getUrl();
        if (url == null) return TYPE_NONE;

        String host = url.getHost();
        if (host == null) return TYPE_NONE;

        switch (host) {
            case "codeload.github.com":
            case "raw.githubusercontent.com":
            case "release-assets.githubusercontent.com":
				if("/favicon.ico".equals(url.getPath()))return TYPE_NONE;
                return TYPE_GITHUB;

            case "github.com": {
					List<String> paths = url.getPathSegments();
					if (match(paths, GITHUB_RELEASES_PATH, 2) || match(paths, GITHUB_ZIP_PATH, 3)) {
						return TYPE_GITHUB;
					}
					return TYPE_NONE;   // 修复 fall-through，不再落到 sourceforge 分支
				}

            case "sourceforge.net":
              /*  if ("download".equals(url.getLastPathSegment())) {
                    return TYPE_SOURCEFORGE;
                }*/
                return TYPE_NONE;

            default:
                return TYPE_NONE;
        }
    }

    /**
     * 检查路径段是否与给定模式匹配
     *
     * @param paths   实际路径段
     * @param pattern 匹配模式（{@code null} 表示该位置不校验）
     * @param offset  开始比较的起始索引
     */
    private boolean match(List<String> paths, String[] pattern, int offset) {
        if (paths == null || paths.size() <= pattern.length) return false;
        for (int i = offset; i < pattern.length; i++) {
            if (!pattern[i].equals(paths.get(i))) return false;
        }
        return true;
    }

    @Override
    public String[] getWhiteList() {
        // 如需收窄作用范围，可换成具体域名：
        // {"github.com", "codeload.github.com", "raw.githubusercontent.com",
        //  "release-assets.githubusercontent.com", "sourceforge.net"}
        return new String[]{"*"};
    }
	@Override
    public WebResourceResponse hook(HookRequest request, int type) {
        Uri url     = request.getUrl();
        String urlStr   = url.toString();
        String fileName = url.getLastPathSegment();
        Map<String, String> headers = request.getHeaders();

        switch (type) {
            case TYPE_GITHUB:
                callback.download(PROXY_BASE + urlStr, fileName, headers);
                break;

            case TYPE_SOURCEFORGE: {
					List<String> paths = url.getPathSegments();
					if (paths != null && paths.size() >= 2) {
						callback.download(SOURCEFORGE_PREFIX + urlStr,
										  paths.get(paths.size() - 2), headers);
					}
					break;
				}

            default:
                break;
        }

        Map<String, String> responseHeaders = new HashMap<>();
        return new WebResourceResponse(
			"text/plain",
			"utf-8",
			200,
			"No Content",
			responseHeaders,
			new ByteArrayInputStream("已触发下载加速".getBytes(StandardCharsets.UTF_8))
        );
    }

	@Override
	public HookRequest overrideUrlLoad(HookRequest hookRequest,int type)
	{
		switch (type) {
            case TYPE_GITHUB:
                return HookReq.from(PROXY_BASE + hookRequest.getUrlString(), hookRequest.getHeaders());

            case TYPE_SOURCEFORGE: {
					List<String> paths = hookRequest.getUrl().getPathSegments();
					if (paths != null && paths.size() >= 2) {
						return HookReq.from(SOURCEFORGE_PREFIX + hookRequest.getUrlString(),
										   hookRequest.getHeaders());
					}
					break;
				}

            default:
                break;
			}
		return hookRequest;
	}
	
}


