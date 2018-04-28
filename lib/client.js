/*
 * Copyright (c) 2015 Jan Van Buggenhout.  All rights reserved.
 */

var dgram = require('dgram');
var util = require('util');
var dns = require('dns');
var os = require('os');
var Receiver = require('./receiver');
var message = require('./protocol/message');
var PDU = require('./protocol/pdu');
var varbind = require('./protocol/varbind');
var data = require('./protocol/data');

var request_id = 1;

function
Client(options)
{
	Receiver.call(this, options);
	this._callbacks = {};
	this._activeRequests = {};
	this._socket = this.createSocket(options.family || 'udp4');
	this._startuptime = 0;
	this.__defineSetter__('startuptime', function (t) {
		if (typeof (t) === 'number')
			this._startuptime = t;
		else
			throw new TypeError('startuptime must be an integer');
	});
	this.__defineGetter__('hostip', function () { return _hostip; });
	var client = this;
	setInterval(function() {checkResend(client)}.bind(this), 1000);	
}
util.inherits(Client, Receiver);

function getUptime(client)
{
	return (Math.floor((Date.now() / 10) - (client._startuptime * 100)));
}

function checkResend(client) {
	var timeout = 5000; //5 seconds
	var cutofftime = new Date()-timeout;
	for (var reqID in client._activeRequests) {
		var activeRequest = client._activeRequests[reqID]
		if (activeRequest.time<cutofftime) {
			if (activeRequest.try>3) {
				activeRequest.cb();
				delete client._activeRequests[reqID];
			} else {
				activeRequest.time=new Date();
				client._socket.send(activeRequest.req._raw.buf, 0, activeRequest.req._raw.len, activeRequest.port, activeRequest.ip,
					function (err, bytes)
					{
						if (err)
							console.log(err); // FIXME: meh
					});
				activeRequest.try++;
			}
		}
	}
}

function send(client, ip, port, req, cb) {
	if (typeof (cb) !== 'undefined' && typeof (cb) !== 'function')
		throw new TypeError('cb must be a function');


	if (cb && 'request_id' in req.pdu)
		client._callbacks[req.pdu.request_id] = cb;
	
	req.encode();
			
	var request = {id: req.pdu.request_id, client: client, ip: ip, port: port, req: req, cb: cb, try: 1, time: new Date()};
	client._activeRequests[req.pdu.request_id] = request;
	client._socket.send(req._raw.buf, 0, req._raw.len, port, ip,
	function (err, bytes)
	{
		if (err)
			console.log(err); // FIXME: meh
	});
}

function OIDNull(oid)
{
	return varbind.createVarbind({
		oid: oid,
		data: data.createData({ type: 'Null', value: 5 })
	});
}

Client.prototype._process_msg = function _process_msg(msg) {
	switch (msg.pdu.op) {
	case PDU.Response:
		this._callbacks[msg.pdu.request_id](msg);
		delete this._callbacks[msg.pdu.request_id];
		delete this._activeRequests[msg.pdu.request_id];
		break;
	case PDU.Trap:
	case PDU.InformRequest:
	case PDU.SNMPv2_Trap:
	case PDU.GetRequest:
	case PDU.SetRequest:
	case PDU.GetNextRequest:
	case PDU.GetBulkRequest:
	case PDU.Report:
	default:
		Receiver.prototype._process_msg.call(this, msg);
		break;
	}
};

Client.prototype.get = function (ip, community, version, oid, cb) {
	send(this, ip, 161, message.createMessage({
		version: version,
		community: community,
		pdu: PDU.createPDU({
			op: PDU.GetRequest,
			request_id: request_id++,
			varbinds: [ OIDNull(oid) ]
		})
	}), cb);
};

Client.prototype.getNext = function (ip, community, version, oid, cb) {
	send(this, ip, 161, message.createMessage({
		version: version,
		community: community,
		pdu: PDU.createPDU({
			op: PDU.GetNextRequest,
			request_id: request_id++,
			varbinds: [ OIDNull(oid) ]
		})
	}), cb);
};

Client.prototype.set = function (ip, community, version, oid, value, cb) {
	send(this, ip, 161, message.createMessage({
		version: version,
		community: community,
		pdu: PDU.createPDU({
			op: PDU.SetRequest,
			request_id: request_id++,
			varbinds: [
				varbind.createVarbind({
					oid: oid,
					data: value
				})
			]
		})
	}), cb);
};

var _hostip = '127.0.0.1';
dns.lookup(os.hostname(), function (err, address, family) {
	_hostip = address;
});

Client.prototype.trap = function (ip, community, options, varbinds) {
	if ('specific_trap' in options) {
		if (!('generic_trap' in options))
			options.generic_trap = PDU.enterpriseSpecific;
		if (PDU.enterpriseSpecific == options.generic_trap &&
			!('enterprise' in options))
			throw new TypeError('options.enterprise is required '+
				'for enterpriseSpecific traps');
	}
	if (!('generic_trap' in options))
		throw new TypeError('Need either generic_trap or '+
			'specific_trap');

	var self = this;
	send(this, ip, 162, message.createMessage({
		version: 0,
		community: community,
		pdu: PDU.createPDU({
			op: PDU.Trap,
			enterprise: options.enterprise || '1.3.6.1.4.1.3.1.1',
			generic_trap: options.generic_trap,
			specific_trap: options.specific_trap || 0,
			agent_addr: options.agent_addr || _hostip,
			time_stamp: options.time_stamp || options.uptime ||
					getUptime(self),
			varbinds: varbinds
		})
	}));
};

Client.prototype.getBulk = function (ip, community, non_repeaters, repeaters,
	max_repetitions, cb) {
	var msg = message.createMessage({
		version: 1,
		community: community,
		pdu: PDU.createPDU({
			op: PDU.GetBulkRequest,
			request_id: request_id++,
			varbinds: non_repeaters.map(OIDNull).
				concat(repeaters.map(OIDNull))
		})
	});
	msg.pdu.non_repeaters = non_repeaters.length;
	msg.pdu.max_repetitions = max_repetitions;
	send(this, ip, 161, msg, cb);
};

Client.prototype.SNMPv2_Trap =
Client.prototype.inform = function (ip, community, uptime, oid, varbinds, cb) {
	var self = this;
	send(this, ip, 162, message.createMessage({
		version: 1,
		community: community,
		pdu: PDU.createPDU({
			op: typeof (cb) === 'function' ? PDU.InformRequest :
				PDU.SNMPv2_Trap,
			request_id: request_id++,
			varbinds: [
				varbind.createVarbind({
					// sysUpTime.0
					oid: '1.3.6.1.2.1.1.3.0',
					data: data.createData({
						type: 'TimeTicks',
						value: typeof (uptime) !==
							'undefined' ? uptime :
							getUptime(self)
					})
				}),
				varbind.createVarbind({
					// snmpTrapOID.0
					oid: '1.3.6.1.6.3.1.1.4.1.0',
					data: data.createData({
						type: 'ObjectIdentifier',
						value: oid
					})
				})
			].concat(varbinds)
		})
	}), cb);
};

Client.prototype.close = function () {
	this._socket.unref();
};

module.exports = Client;
