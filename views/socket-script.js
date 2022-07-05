var socket = io();
    socket.on("connect", () => {
        console.log("Checking project");
        socket.emit("check_project", )
    })
    
    socket.on( 'update-upvotes', function( f_str ) {
      document.getElementById( 'upvote-count' ).innerHTML = f_str;
    });