// index.js

/**
 * Required External Modules
 */

 const express = require("express");
 const bp = require('body-parser');
 const fs = require('fs');
 const axios = require('axios');
 const { body,validationResult } = require('express-validator');
 const { spawn, ChildProcess } = require('child_process');
 const path = require("path");
 const https = require( 'https' );
 const sendMail = require('./gmail');
 const keys = require('./keys.json');

/**
 * App Variables
 */

 const options = {
  key: fs.readFileSync('key.pem'),
  cert: fs.readFileSync('cert.pem')
 };

 const app = express();
 const port = process.env.PORT || "8000";
 const http = https.createServer( options, app );
 const io = require( 'socket.io' )( http );
 https.globalAgent.options.ca = fs.readFileSync('node_modules/node_extra_ca_certs_mozilla_bundle/ca_bundle/ca_intermediate_root_bundle.pem');

 let statsData = {}
 let lastRefresh = 0

/**
 *  App Configuration
 */

app.set("views", path.join(__dirname, "views"));
app.set("view engine", "pug");
app.use('/portal', express.static(path.join(__dirname, "public")));
app.use(bp.json())
app.use(bp.urlencoded({ extended: true }))

/**
 * Routes Definitions
 */

 app.get("/portal", (req, res) => {
   if (Date.now() - lastRefresh > 300000) {
    axios.post('https://secureseco.science.uu.nl/api/ds/query', {
      queries:[
        {
          refId:"projects",
          datasource:{
            uid:"nueIPUp7z"
          },
          format:"table",
          expr: "avg (cassandra_stats{name=~\".*:estimatedpartitioncount:.*\", table=\"projects\"})",
          instant:true
        },
        {
          refId:"methods",
          datasource:{
            uid:"nueIPUp7z"
          },
          format:"table",
          expr: "avg (cassandra_stats{name=~\".*:estimatedpartitioncount:.*\", table=\"methods\"})",
          instant:true
        },
        {
          refId:"authors",
          datasource:{
            uid:"nueIPUp7z"
          },
          format:"table",
          expr: "avg (cassandra_stats{name=~\".*:estimatedpartitioncount:.*\", table=\"author_by_id\"})",
          instant:true
        },
        {
          refId:"vulnerabilities",
          datasource:{
            uid:"nueIPUp7z"
          },
          format:"table",
          expr: "sum (api_vulnerabilities_total)",
          instant:true
        },
        {
          refId:"vulnChange",
          datasource:{
            uid:"nueIPUp7z"
          },
          format:"table",
          expr: "sum (increase(api_vulnerabilities_total[24h]))",
          instant:true
        },
        {
          refId:"projectChange",
          datasource:{
            uid:"nueIPUp7z"
          },
          format:"table",
          expr: "avg (delta(cassandra_stats{name=~\".*:estimatedpartitioncount:.*\", table=\"projects\"}[24h]))",
          instant:true
        },
        {
          refId:"methodChange",
          datasource:{
            uid:"nueIPUp7z"
          },
          format:"table",
          expr: "sum by (Client) (delta(api_methods_total[24h]))",
          instant:true
        },
        {
          refId:"recentProjects",
          datasource:{
            uid:"nueIPUp7z"
          },
          format:"table",
          expr: "topk(5, api_recent_projects_seconds)",
          instant:true
        },
        {
          refId:"recentVulns",
          datasource:{
            uid:"nueIPUp7z"
          },
          format:"table",
          expr: "topk(5, api_recent_vulnerabilities_seconds)",
          instant:true
        }
      ],
      from:"now-6h",
      to:"now"
    },{
      headers: {
        Authorization: keys.grafana_token,
      }
    }).then(result => {      
      let formatter = Intl.NumberFormat('en', { notation: 'compact' });
      let formatterPercent = Intl.NumberFormat('en', { style: 'percent', minimumFractionDigits: 3 });
      //console.log(result.data.results.methodChange.frames);
      statsData = {
        projects: formatter.format(result.data.results.projects.frames[0].data.values[1][0]),
        methods:  formatter.format(result.data.results.methods.frames[0].data.values[1]),
        coverage: formatterPercent.format(result.data.results.projects.frames[0].data.values[1][0]/28000000),
        authors:  formatter.format(result.data.results.authors.frames[0].data.values[1]),
        vulnerabilities:  formatter.format(result.data.results.vulnerabilities.frames[0].data.values[1]),
        vulnChange:  formatter.format(result.data.results.vulnChange.frames[0].data.values[1]),
        projectChange:   formatter.format(Math.round(Math.max(0, result.data.results.projectChange.frames[0].data.values[1]))),
        methodChange: result.data.results.methodChange.frames.map(x => {if (x.data.values[1] > 0) {return {name: x.schema.name.substring(9, x.schema.name.length - 2), value: formatter.format(x.data.values[1])};}}),
        recentProjects: result.data.results.recentProjects.frames,
        recentVulns: result.data.results.recentVulns.frames,
        }
      res.render("index", { title: "Home", data: statsData, errors: {} });
    }).catch(error => {
      console.log(error);
    });} else {
    res.render("index", { title: "Home", data: statsData, errors: {} });
    }
  });
  
  check_project = [
    // Validate and sanitize the name field.
    body('url', 'URL required').trim().isLength({ min: 1 }),
    body('url', 'Incorrect URL').isURL(),
    body('email', 'email required').trim().isLength({ min: 1 }),
    body('email', 'incorrect email').isEmail(),
    //body('password', 'Incorrect password format').trim().isLength({ min: 1 }).escape(),
  
    // Process request after validation and sanitization.
    (req, res, next) => {      

      // Extract the validation errors from a request.
      const errors = validationResult(req);
  
      if (!errors.isEmpty()) {
        // There are errors. Render the form again with sanitized values/error messages.
        res.render('index', { title: "Home", data: statsData, errors: errors.array()});
        return;
      }
      else {

        /*if (req.body.password != 'password') {
          // There are errors. Render the form again with sanitized values/error messages.
          res.render('index', { title: "Home", data: statsData, errors: [{msg: 'Incorrect password'}]});
          return;
        }*/
        // Data from form is valid.
        console.log(req.body.url)

        res.render('user', {title: "Check", data: {url: req.body.url, email: req.body.email}});
      }
    }
  ]

  app.post('/portal', check_project);

  io.on( 'connection', function( socket ) {
    console.log( 'a user has connected!' );
    
    socket.on( 'disconnect', function() {
        console.log( 'user disconnected' );
    });
    
    socket.on( 'check-project', function( data ) {
      const data_json = JSON.parse(data.replaceAll("&quot;", "\""));
      const url = data_json.url.replace(/\/\s*$/, "");
      var result = "";

      const command = spawn('docker',  ["run", "--rm", "--name", `controller-container-${url.substring(url.lastIndexOf('/')+1)}`,
        '--entrypoint=./controller/build/searchseco', '-e', `github_token=${keys.github_token}`, '--cpus=2',
        '-e', `worker_name=portal-check-${url.substring(url.lastIndexOf('/')+1)}`, 'searchseco/controller', 'check', url]);

      command.on('exit', function (code, signal) {
        console.log('child process exited with ' +
                    `code ${code} and signal ${signal}`);
        sendReport(data_json.email, url, result);        
        socket.disconnect();
      });

      command.on('error', function (code, signal) {
        console.log('child process errored with ' +
                    `code ${code} and signal ${signal}`);
        socket.disconnect();
      });

      command.stdout.on('data', (data) => {
        socket.emit( 'update-logs', String(data) );
        result += String(data);
        //console.log(`child stdout:\n${data}`);
      });

      command.stderr.on('data', (data) => {
        socket.emit( 'update-logs', String(data) );
        result += String(data);
        //console.log(`child stderr:\n${data}`);
      });
    });
  });

  app.get("/portal/projects", (req, res) => {
    res.render('projects', {title: "Projects counter"});
  });

  app.get("/portal/projectcounter", (req, res) => {
    axios.post('https://secureseco.science.uu.nl/api/ds/query', {
      queries:[
        {
          refId:"projects",
          datasource:{
            uid:"nueIPUp7z"
          },
          format:"table",
          expr: "avg (cassandra_stats{name=~\".*:estimatedpartitioncount:.*\", table=\"projects\"})",
          instant:true
        }
      ],
      from:"now-6h",
      to:"now"
    },{
      headers: {
        Authorization: keys.grafana_token,
      }
    }).then(result => {      
      let formatter = Intl.NumberFormat('en', { notation: 'standard' });
      res.send(formatter.format(Math.round(result.data.results.projects.frames[0].data.values[1][0])));
    }).catch(error => {
      console.log(error);
    });    
  });

  sendReport = (email, url, result) => {
    const projectName = url.substring(url.lastIndexOf('/')+1);

    const fileAttachment = [{
        filename: `${projectName}.txt`,
        content: result,
      }];

    const options = {
      to: email,
      subject: 'SearchSECO report for ' + projectName,
      text: 'Thank you for using the SearchSECO system.\nAttached is the report for the project: ' + url,
      attachments: fileAttachment,
      textEncoding: 'base64',
    };

    sendMail(options)
      .then((messageId) => console.log(`Message sent succesfully: ${messageId}`))
      .catch((err) => console.error(err));    
  }

/**
 * Server Activation
 */

 http.listen(port, () => {
    console.log(`Listening to requests on https://localhost:${port}/portal`);
  });

  const bodyParser = require('body-parser');
const { Console } = require("console");

  const middlewares = [
    // ...
    bodyParser.urlencoded({ extended: true }),
  ];