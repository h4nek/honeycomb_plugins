# -*- coding: utf-8 -*-
"""Default Tarpit Honeycomb Service."""
import os

import requests
from six.moves.socketserver import ThreadingMixIn
from six.moves.BaseHTTPServer import HTTPServer
from six.moves.SimpleHTTPServer import SimpleHTTPRequestHandler
import subprocess
from subprocess import call, Popen
from threading import Event

from base_service import ServerCustomService

DEFAULT_IP = "127.0.0.1"
DEFAULT_PORT = 8888
EVENT_TYPE_FIELD_NAME = "event_type"
TARPIT_ALERT_TYPE_NAME = "tarpit"
ORIGINATING_IP_FIELD_NAME = "originating_ip"
ORIGINATING_PORT_FIELD_NAME = "originating_port"
REQUEST_FIELD_NAME = "request"
#DEFAULT_SERVER_VERSION = "nginx"


class HoneyHTTPRequestHandler(SimpleHTTPRequestHandler, object):
    """Simple HTTP Request Handler."""

    #server_version = DEFAULT_SERVER_VERSION

    def version_string(self):
        """HTTP Server version header."""
        return self.server_version

    def send_head(self, *args, **kwargs):
        """Handle every request by raising an alert."""
        self.alert(self)
        return super(HoneyHTTPRequestHandler, self).send_head(*args, **kwargs)

    def log_error(self, msg, *args):
        """Log an error."""
        self.log_message("error", msg, *args)

    def log_request(self, code="-", size="-"):
        """Log a request."""
        self.log_message("debug", '"{:s}" {:s} {:s}'.format(self.requestline, str(code), str(size)))

    def log_message(self, level, msg, *args):
        """Send message to logger with standard apache format."""
        getattr(self.logger, level)("{:s} - - [{:s}] {:s}".format(self.client_address[0], self.log_date_time_string(),
                                                                  msg % args))


class SimpleHTTPService(ServerCustomService):
    """Simple HTTP Honeycomb Service."""

    httpd = None

    def __init__(self, *args, **kwargs):
        super(SimpleHTTPService, self).__init__(*args, **kwargs)

    def alert(self, request):
        """Raise an alert."""
        params = {
            EVENT_TYPE_FIELD_NAME: SIMPLE_HTTP_ALERT_TYPE_NAME,
            ORIGINATING_IP_FIELD_NAME: request.client_address[0],
            ORIGINATING_PORT_FIELD_NAME: request.client_address[1],
            REQUEST_FIELD_NAME: " ".join([request.command, request.path]),
        }
        self.add_alert_to_queue(params)

    def on_server_start(self):
        """Initialize Service."""
        os.chdir(os.path.join(os.path.dirname(__file__), "www"))
        requestHandler = HoneyHTTPRequestHandler
        requestHandler.alert = self.alert
        requestHandler.logger = self.logger
        #requestHandler.server_version = self.service_args.get("version", DEFAULT_SERVER_VERSION)

        port = self.service_args.get("port", DEFAULT_PORT)
        threading = self.service_args.get("threading", False)
        if threading:
            self.httpd = ThreadingHTTPServer(("", port), requestHandler)
        else:
            self.httpd = HTTPServer(("", port), requestHandler)

        self.signal_ready()
        self.logger.info("Starting {}Simple HTTP service on port: {}".format("Threading " if threading else "", port))
        self.httpd.serve_forever()

    def on_server_shutdown(self):
        """Shut down gracefully."""
        if self.httpd:
            self.httpd.shutdown()
            self.logger.info("Simple HTTP service stopped")
            self.httpd = None

    def test(self):
        """Test service alerts and return a list of triggered event types."""
        event_types = list()
        self.logger.debug("executing service test")
        requests.get("http://localhost:{}/".format(self.service_args.get("port", DEFAULT_PORT)))
        event_types.append(SIMPLE_HTTP_ALERT_TYPE_NAME)

        return event_types

    def __str__(self):
        return "Simple HTTP"

class TarpitService(ServerCustomService):
    """Simple Tarpit Honeycomb Service"""
    
    proc = None
    proc_tcpdump = None
    
    def __init__(self, *args, **kwargs):
        super(TarpitService, self).__init__(*args, **kwargs)
        self.cur_path = os.path.dirname(os.path.realpath(__file__))
        self.active = True
        
    def alert(self, request):
        """Raise an alert."""
        params = {
            EVENT_TYPE_FIELD_NAME: TARPIT_ALERT_TYPE_NAME,
            ORIGINATING_IP_FIELD_NAME: request.client_address[0],
            ORIGINATING_PORT_FIELD_NAME: request.client_address[1],
            REQUEST_FIELD_NAME: " ".join([request.command, request.path]),
        }
        self.add_alert_to_queue(params)

    def on_server_start(self):
        """Initialize Service."""
        #os.chdir(os.path.join(os.path.dirname(__file__), "www"))
        requestHandler = HoneyHTTPRequestHandler
        requestHandler.alert = self.alert
        requestHandler.logger = self.logger
        #requestHandler.server_version = self.service_args.get("version", DEFAULT_SERVER_VERSION)

        ip = self.service_args.get("ip", DEFAULT_IP)
        port = self.service_args.get("port", DEFAULT_PORT)
        threading = self.service_args.get("threading", False)
        
        
        tarpit_log = open(self.cur_path + "/testfiles/simple_tarpit_log.out", 'a+')
        self.proc = Popen("nc -lvkd " + ip + " " + str(port), stdout=tarpit_log, stderr=subprocess.STDOUT, shell=True) # listens on given interface and port until killed, redirects stderr and stdout to file, runs in background
        # shell example: nc -lvdk 192.168.1.100 22 &> ./testfiles/test.out &
        #self.proc = Popen("nc -lvkd " + ip + " " + str(port) + " &> " + self.cur_path + "/testfiles/simple_tarpit_log.out &", shell=True)
        
        
        tcpdump_log = open(self.cur_path + "/testfiles/tcpdump.out", 'a+')
        self.proc_tcpdump = Popen("tcpdump -nvvv dst host " + ip + " and tcp port " + str(port), stdout=tcpdump_log, stderr=subprocess.STDOUT, shell= True)
        
        #self.server = T
        self.signal_ready()
        self.logger.info("Starting {}Tarpit service on interface: {}, port: {}".format("Threading " if threading else "", ip, port))
        
        while self.active: # should be running in a thread until termination
            pass
        
        tarpit_log.close()
        tcpdump_log.close()
        #self.server.serve_forever()
        #self.httpd.serve_forever()

    def on_server_shutdown(self):
        """Shut down gracefully."""
        self.active = False
        if self.proc:
            self.proc.kill()
            self.proc.communicate()
        if self.proc_tcpdump:
            self.proc_tcpdump.kill()
            self.proc_tcpdump.communicate()
        self.logger.info("Tarpit service stopped")

    def test(self):
        """Test service alerts and return a list of triggered event types."""
        event_types = list()
        self.logger.debug("executing service test")
        requests.get("http://localhost:{}/".format(self.service_args.get("port", DEFAULT_PORT)))
        event_types.append(SIMPLE_HTTP_ALERT_TYPE_NAME)

        return event_types

    def __str__(self):
        return "Tarpit"

service_class = TarpitService
