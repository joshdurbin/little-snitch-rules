package io.durbs.lsrules

import com.google.common.base.Charsets
import com.google.common.io.ByteStreams
import groovy.json.JsonOutput
import groovy.transform.CompileStatic
import groovy.util.logging.Slf4j
import io.javalin.Javalin

import java.util.concurrent.TimeUnit
import java.util.concurrent.CountDownLatch
import java.util.concurrent.atomic.AtomicReference
import java.util.regex.Matcher
import java.util.regex.Pattern
import java.util.zip.DeflaterOutputStream
import java.util.zip.GZIPInputStream
import java.util.zip.GZIPOutputStream

@CompileStatic
@Slf4j
class App {

    static final String urlString = 'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts'
    static final URL url = urlString.toURL()
    static final Pattern regexPattern = ~'^0.0.0.0 ([^#]*)(#.*)?'
    static final Long backgroundThreadSleepDuration = TimeUnit.MILLISECONDS.convert(6L, TimeUnit.HOURS)
    static final String forceRePopulateEndpoint = '/forceRePopulate'
    static final String bindAddress = '0.0.0.0' // this needs to be 0.0.0.0 to bind to all interfaces and work most easily in a container
    static final Integer bindPort = 9999
    static final String decompressQueryParam = 'q'

    final CountDownLatch firstLoadLatch = new CountDownLatch(1)
    final AtomicReference compressedPayload = new AtomicReference<byte[]>()

    void populateData() {

        log.info("Pulling hosts data from ${urlString}")

        final Set entries = new LinkedHashSet<String>()

        try {
            url.eachLine('utf-8') { String line ->
                final Matcher matcher = line =~ regexPattern
                matcher.find()
                if (matcher) {
                    String hostname = matcher.group(1)
                    if (hostname != '0.0.0.0') {
                        entries.add(hostname)
                    }
                }
            }
        } catch (Exception exception) {
            log.error("An error occurred trying to resolve or process the data. Will try again in ${backgroundThreadSleepDuration} ms or POST to ${forceRePopulateEndpoint} to trigger again")
        }

        final String response = JsonOutput.toJson([name: 'Block adware and malware',
                                                   description: 'Little snitch rules to block adware and malware websites. Host lists from Steven Black.',
                                                   rules: entries.collect { String hostname -> [action:'deny', process:'any', 'remote-domains': hostname] }])

        final OutputStream out = new ByteArrayOutputStream()
        final DeflaterOutputStream gzip = new GZIPOutputStream(out)
        gzip.write(response.getBytes('utf-8'))
        gzip.flush()
        gzip.close()

        compressedPayload.set(out.toByteArray())
    }

    void createBackgroundThread() {

        log.info("Starting background thread...")

        Thread.start {

            while (true) {

                populateData()

                if (firstLoadLatch) {
                    firstLoadLatch.countDown()
                }

                log.debug("Sleeping for ${backgroundThreadSleepDuration} ms")
                sleep(backgroundThreadSleepDuration)
            }
        }
    }

    static void main(String[] args) {

        final App app = new App()
        app.createBackgroundThread()
        app.firstLoadLatch.await()

        final Javalin javalin = Javalin.create().start(bindAddress, bindPort)
        javalin.get('/', ctx -> {
            if (ctx.queryParamMap().containsKey(decompressQueryParam)) {
                // Or, if the client is unable decompress gzip Content or Transfer encoding, we should uncompress server side.
                ctx.result(new String(ByteStreams.toByteArray(new GZIPInputStream(new ByteArrayInputStream(app.compressedPayload.get() as byte[]))), Charsets.UTF_8))
            } else {
                ctx.header('Content-Encoding', 'gzip')
                ctx.header('Transfer-Encoding', 'gzip')
                ctx.header('Content-Type', 'application/json')
                ctx.result(app.compressedPayload.get() as byte[])
            }
        })
        javalin.post(app.forceRePopulateEndpoint, ctx -> {
            app.populateData()
            ctx.redirect('/')
        })
    }
}
