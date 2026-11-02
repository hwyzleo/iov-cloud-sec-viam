package net.hwyz.iov.cloud.sec.viam.service.adapter.web.security;

import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

/**
 * 缓存请求体包装（G-4）：验签需要读取原始 body 计算摘要，控制器随后仍需读取 body。
 *
 * @author hwyz_leo
 */
public class CachedBodyHttpServletRequest extends HttpServletRequestWrapper {

    private final byte[] body;

    public CachedBodyHttpServletRequest(HttpServletRequest request) throws IOException {
        super(request);
        this.body = request.getInputStream().readAllBytes();
    }

    public byte[] getBody() {
        return body;
    }

    @Override
    public ServletInputStream getInputStream() {
        return new CachedServletInputStream(new ByteArrayInputStream(body));
    }

    @Override
    public java.io.BufferedReader getReader() {
        return new java.io.BufferedReader(new java.io.InputStreamReader(getInputStream(), StandardCharsets.UTF_8));
    }

    private static final class CachedServletInputStream extends ServletInputStream {

        private final InputStream source;

        private CachedServletInputStream(InputStream source) {
            this.source = source;
        }

        @Override
        public int read() throws IOException {
            return source.read();
        }

        @Override
        public boolean isFinished() {
            return true;
        }

        @Override
        public boolean isReady() {
            return true;
        }

        @Override
        public void setReadListener(ReadListener readListener) {
            throw new UnsupportedOperationException("not supported");
        }
    }
}
