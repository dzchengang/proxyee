package com.github.monkeywie.proxyee;

import com.github.monkeywie.proxyee.intercept.HttpProxyInterceptInitializer;
import com.github.monkeywie.proxyee.intercept.HttpProxyInterceptPipeline;
import com.github.monkeywie.proxyee.intercept.common.FullRequestIntercept;
import com.github.monkeywie.proxyee.intercept.common.FullResponseIntercept;
import com.github.monkeywie.proxyee.server.HttpProxyServer;
import com.github.monkeywie.proxyee.server.HttpProxyServerConfig;
import io.netty.handler.codec.http.FullHttpResponse;
import io.netty.handler.codec.http.HttpRequest;
import io.netty.handler.codec.http.HttpResponse;

/**
 * @Author LiWei
 * @Description
 * @Date 2019/9/23 17:30
 */
public class HttpProxyServerApp {
   /* public static void main(String[] args) {
        System.out.println("start proxy server");
        int port = 9999;
        if (args.length > 0) {
            port = Integer.valueOf(args[0]);
        }
        new HttpProxyServer().start(port);
    }*/

    public static void main(String[] args) {
        HttpProxyServerConfig config = new HttpProxyServerConfig();
        config.setHandleSsl(true);
        new HttpProxyServer()
                .serverConfig(config)
                .proxyInterceptInitializer(new HttpProxyInterceptInitializer() {
                    @Override
                    public void init(HttpProxyInterceptPipeline pipeline) {
                     /*   pipeline.addLast(new FullRequestIntercept() {
                            @Override
                            public boolean match(HttpRequest httpRequest, HttpProxyInterceptPipeline pipeline) {
                                String host = httpRequest.headers().get("host");
                                return host.contains("lefuapp.lefuyunma.com");
                            }
                        });*/

                        pipeline.addLast(new FullResponseIntercept() {
                            @Override
                            public boolean match(HttpRequest httpRequest, HttpResponse httpResponse, HttpProxyInterceptPipeline pipeline) {
                                String host = httpRequest.headers().get("host");
                                return host.contains("lefuapp.lefuyunma.com");
                            }

                            @Override
                            public void handleResponse(HttpRequest httpRequest, FullHttpResponse httpResponse, HttpProxyInterceptPipeline pipeline) {
                                String contentType = httpResponse.headers().get("Content-Type");
                                System.out.println(contentType);
                            }
                        });
                    }
                })
                .start(9999);
    }
}
