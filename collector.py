#!/usr/bin/python

import multitail2
import hpfeeds

import sys
import datetime
import json
import hpfeeds
import logging
import re

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

ch = logging.StreamHandler(sys.stdout)
ch.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
logger.addHandler(ch)

def parse(line):
#Apr  3 15:44:14 DC1 smbd_audit: shareuser|192.168.56.22|fileshare|close|ok|ha.txt
    regex = r'^(?P<timestamp>\S{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(?P<hostname>\S+)\s(?P<flag>\w+):\s+(?P<username>\w+|\d+)\|(?P<source_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\|(?P<fileshare_name>\w+|\d+)\|(?P<action>\w+)\|(?P<status>\w+)\|(?P<filename>\S*)'
    match = re.match(regex, line)
    if match:
        res = match.groupdict()
        for name in res.keys():
            if not res[name]:
                del res[name]
        return res
    return None

def hpfeeds_connect(host, port, ident, secret):
    try:
        connection = hpfeeds.new(host, port, ident, secret)
    except hpfeeds.FeedException as e:
        logger.error('feed exception: %s'%e)
        sys.exit(1)
    logger.info('connected to %s (%s:%s)'%(connection.brokername, host, port))
    return connection

def main():
    cfg = {
        'host' : '',
        'port' : 10000,
        'channel' : '',
        'id' : '',
        'secret' : '',
        'tail_file' : ''
    }

    if len(sys.argv) > 1:
        logger.info("Parsing config file: %s"%sys.argv[1])
        cfg.update(json.load(file(sys.argv[1])))

        for name,value in cfg.items():
            if isinstance(value, basestring):
                # hpfeeds protocol has trouble with unicode, hence the utf-8 encoding here
                cfg[name] = value.encode("utf-8")
    else:
        logger.warning("Warning: no config found, using default values for hpfeeds server")
    publisher  = hpfeeds_connect(cfg['host'], cfg['port'], cfg['id'], cfg['secret'])

    tail = multitail2.MultiTail(cfg['tail_file'])
    for filemeta, line in tail:
        record = parse(line)
        if record:
            publisher.publish(cfg['channel'], json.dumps(record))
            logger.debug(json.dumps(record))
    publisher.stop()
    return 0

if __name__ == '__main__':
    try: 
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(0)

