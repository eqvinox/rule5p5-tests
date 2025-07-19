const ws_url = document.URL.replace("http:", "ws:") + "ws";
const socket = new WebSocket(ws_url);

function journal_msg(msg) {
	let journal = document.getElementById("journal");
	let div = document.createElement("div");
	div.innerText = msg;
	journal.prepend(div);

	return div;
}

socket.addEventListener("open", (event) => {
	socket.send("init");
});

socket.addEventListener("message", (event) => {
	console.log("MSG: ", event.data);
	if ((m = event.data.match(/connect (.*)/))) {
		const url = m[1];
		let req = new XMLHttpRequest();
		req.onload = (e) => {
			console.log(`XHR complete for ${url}`);
			socket.send(`complete ${url}`);
			journal_msg(`complete ${url}`).style.color = "#060";
		};
		req.ontimeout = () => {
			console.log(`XHR timeout for ${url}`);
			socket.send(`timeout ${url}`);
			journal_msg(`timeout ${url}`).style.color = "#a06";
		};
		req.onerror = (e) => {
			console.log(`XHR error for ${url}: ${req.statusText}`);
			socket.send(`error ${url} ${req.statusText}`);
			journal_msg(`error ${url} ${req.statusText}`).style.color = "#f00";
		};
		req.open("GET", url, true);
		req.timeout = 1000; /* ms */
		console.log(`XHR send ${url}`);
		journal_msg(`connecting ${url}`);
		req.send();
	} else if ((m = event.data.match(/message (.*)/))) {
		const msg = m[1];
		journal_msg(`message: ${msg}`).style.color = "#00c";
	} else if ((m = event.data.match(/manual (.*)/))) {
		const addr = m[1];
		let manual = document.getElementById("manual");
		manual.innerText = `please ssh/connect to ${addr}`;
		manual.style.display = "block";
	} else if ((m = event.data.match(/manual-clear/))) {
		let manual = document.getElementById("manual");
		manual.innerText = "";
		manual.style.display = "none";
	}
});

socket.addEventListener("close", (event) => {
	console.log(`WS closed ${event.reason}`);
	journal_msg(`control connection closed (${event.reason})`).style.backgroundColor = "#ccf";
});

socket.addEventListener("error", (event) => {
	console.log("WS error");
	journal_msg("control connection error").style.backgroundColor = "#fad";
});
