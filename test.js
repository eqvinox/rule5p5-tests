const ws_url = document.URL.replace("http:", "ws:") + "ws";
const socket = new WebSocket(ws_url);

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
		};
		req.ontimeout = () => {
			console.log(`XHR timeout for ${url}`);
			socket.send(`timeout ${url}`);
		};
		req.onerror = (e) => {
			console.log(`XHR error for ${url}: ${req.statusText}`);
			socket.send(`error ${url} ${req.statusText}`);
		};
		req.open("GET", url, true);
		req.timeout = 1000; /* ms */
		console.log(`XHR send ${url}`);
		req.send();
	}
});
