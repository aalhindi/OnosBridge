/*
 * Copyright 2024-present Open Networking Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.firewall.app;

import org.onlab.packet.Ethernet;
import org.onlab.packet.IPacket;
import org.onlab.packet.IPv4;
import org.onlab.packet.TCP;
import org.onlab.packet.UDP;
import org.onosproject.cfg.ComponentConfigService;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.DeviceId;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketService;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Modified;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse.BodyHandlers;
import java.time.Duration;
import java.util.Dictionary;
import java.util.Properties;
import java.util.concurrent.ForkJoinPool;
import java.util.Map;
import java.util.HashMap;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpExchange;
 
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
 

import static org.onlab.util.Tools.get;

@Component(immediate = true,
           service = {SomeInterface.class},
           property = {
               "someProperty=Some Default String Value",
           })
    public class AppComponent implements SomeInterface{

    private final Logger log = LoggerFactory.getLogger(getClass());

    /** Some configurable property. */
    private String someProperty;
    private String responseMSG;
    private final InternalPacketProcessor packetListener = new InternalPacketProcessor();

    HttpServer server = null;

    private HttpClient client= HttpClient.newBuilder()
                            .connectTimeout(Duration.ofSeconds(10))
                            .build();
    int largestPacket = 0;
    private int allowed_count = 0, denied_count = 0, packet_count = 0, failed_count=0, all_count=0, response_count=0;
    private ApplicationId appId;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected CoreService coreService;
    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected ComponentConfigService cfgService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected PacketService packetService;

    @Activate
    protected void activate() {
        try {
            server = HttpServer.create(new InetSocketAddress(5000), 0);
            server.createContext("/", new RootHandler());
            server.createContext("/reset", new ResetHandler());
            server.setExecutor(null); // Use the default executor
            server.start();
 
            log.info("*_*_*_*_*_*_*_*_ Server is running on port 5000");
        } catch (IOException e) {
            log.error(e.getMessage(), e);
        }
        appId = coreService.registerApplication("org.firewall.app");
        cfgService.registerProperties(getClass());
        packetService.addProcessor(packetListener, PacketProcessor.director(7));

        log.info("*_*_*_*_*_*_*_*_ Firewall Started");
    }

    @Deactivate
    protected void deactivate() {
        server.stop(0);
        log.info("*_*_*_*_*_*_*_*_ Server Stopped");
        packetService.removeProcessor(packetListener);
        cfgService.unregisterProperties(getClass(), false);
        log.info("*_*_*_*_*_*_*_*_ Firewall Stopped");
    }

    @Modified
    public void modified(ComponentContext context) {
        Dictionary<?, ?> properties = context != null ? context.getProperties() : new Properties();
        if (context != null) {
            someProperty = get(properties, "someProperty");
        }
        log.info("Reconfigured");
    }

    private class ResetHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException 
        {
            allowed_count = 0; denied_count = 0;
             packet_count = 0; failed_count=0; all_count=0; response_count=0;
            // handle the request
            String response = "All counters are resetted " +"\n";
            exchange.sendResponseHeaders(200, response.length());
            OutputStream os = exchange.getResponseBody();
            os.write(response.getBytes());
            os.close();
        }
    }

    private class RootHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException 
        {
            // handle the request
            String response = "Hello, this is RootHandlera simple HTTP server response! " + String.valueOf(failed_count)+"\n";
            exchange.sendResponseHeaders(200, response.length());
            OutputStream os = exchange.getResponseBody();
            os.write(response.getBytes());
            os.close();
        }
    }

    private class InternalPacketProcessor implements PacketProcessor {
        @Override
        public void  process(PacketContext packetContext) {
            if (packetContext != null && packetContext.inPacket() != null) 
            {
                Ethernet ethernet = packetContext.inPacket().parsed();
                all_count++;
                
                if (ethernet != null && ethernet.getEtherType() == Ethernet.TYPE_IPV4 && ethernet.getPayload() instanceof IPv4 )
                {
                    packet_count++;
                    if ( packet_count % 50000 == 0 )
                            log.info("*_*_*_*_*_*_"
                                + " ALL:" + all_count
                                + " P:" + packet_count
                                + " A:" + allowed_count
                                + " D:" + denied_count
                                + " F:" + failed_count
                                + "MSG:" + responseMSG
                                +"*_*_*_*_*_*_ ");

                    DeviceId deviceId = packetContext.inPacket().receivedFrom().deviceId();
                    IPv4 packetIPv4 = (IPv4) ethernet.getPayload();
                    String[] ipsAndPorts = extractIP(packetIPv4);
                    
                    if (ipsAndPorts[4].compareTo("ANOTHER") != 0) 
                    {

                        String knative = "http://firewall.default.192.168.56.1.sslip.io/?"
                                        + "s_addr=" + ipsAndPorts[0] 
                                        + "&d_addr=" + ipsAndPorts[1]
                                        + "&s_port=" + ipsAndPorts[2] 
                                        + "&d_port=" + ipsAndPorts[3];
                        
                        byte[] packetBytes = ethernet.serialize();
                                        
                        HttpRequest request;
                        request = HttpRequest.newBuilder()
                            .uri(URI.create(knative))
                            //.headers("Content-Type", "application/x-www-form-urlencoded")
                            .POST(HttpRequest.BodyPublishers.ofByteArray(packetBytes))
                            //.timeout(Duration.ofSeconds(30))
                            .build();
                        
                        
                        client.sendAsync(request, BodyHandlers.ofString())
                            .thenAccept(response -> 
                            {
                                if (response != null && response.body() != null )
                                {
                                    try 
                                    {
                                        response_count++;
                                        String responseMessage = response.body();
                                        if ( ! responseMessage.contains("AZIZ"))
                                        {
                                            failed_count++;
                                            if ( failed_count % 500 == 0 )
                                                log.error("ERRRRROR:"+responseMessage+" failed counter:"+String.valueOf(failed_count));
                                            
                                        }

                                        responseMSG = responseMessage;

                                        if (responseMessage.contains("deny")) {
                                                denied_count++;
                                        } else
                                                allowed_count++;

                                    } catch (Exception e) {
                                        failed_count++;
                                        log.error(e.getMessage(),e);
                                    }
                                }
                            })
                            .exceptionally(e ->{
                                failed_count++;
                                log.error(e.getMessage(),e);
                                return null;
                            });
                        
                        
                    }                    
                }
            }
            

        }

        private String[] extractIP(IPv4 packetIPv4) {
            String[] ipsAndPorts = new String[5]; // sourceIP - destIP , sourcePort, destPort, TCP or UDP or ICMP

            ipsAndPorts[0] = IPv4.fromIPv4Address(packetIPv4.getSourceAddress()).trim();
            ipsAndPorts[1] = IPv4.fromIPv4Address(packetIPv4.getDestinationAddress()).trim();

            IPacket payload = packetIPv4.getPayload();
            if (payload instanceof TCP) {
                TCP tcpPacket = (TCP) payload;
                ipsAndPorts[2] = String.valueOf(tcpPacket.getSourcePort()).trim();
                ipsAndPorts[3] = String.valueOf(tcpPacket.getDestinationPort()).trim();
                ipsAndPorts[4] = "TCP";

                // int payloadSize = tcpPacket.getPayload().serialize().length;
                // if (payloadSize > largestPacket)
                //     largestPacket = payloadSize;

                // log.info("Src IP:"+ipsAndPorts[0]+" Dest IP:"+ipsAndPorts[1]+"\n"+ 
                //     "Packet length = "+String.valueOf( tcpPacket.serialize().length)+
                // //"\n1:::"+tcpPacket.getPayload().toString()+
                // "\n Payload size = "+String.valueOf(payloadSize) + "\n"+
                // "Largest Packet = "+String.valueOf(largestPacket));
                // //log.info("2:::"+((TCP) payload).getPayload().getPayload().toString());
                // //log.info("3:::"+((TCP) payload).getPayload().getPayload().getPayload().toString());

            } else if (payload instanceof UDP) {
                ipsAndPorts[2] = String.valueOf(((UDP) payload).getSourcePort()).trim();
                ipsAndPorts[3] = String.valueOf(((UDP) payload).getDestinationPort()).trim();
                ipsAndPorts[4] = "UDP";

            }
            else
                ipsAndPorts[4] = "ANOTHER";

            return ipsAndPorts;
        }
    }

    @Override
    public void someMethod() {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'someMethod'");
    }

}
