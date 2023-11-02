const fs = require('fs')
const { spawn } = require('child_process');
const { body } = require('express-validator');

exports.getProfile = (req, res) => {
  const profile = JSON.parse(fs.readFileSync("./data.json"))
  res.send(JSON.stringify(profile));
};

exports.updateProfileValidationRules = [
  body('firstname').isString().notEmpty(),
  body('bio').isString().notEmpty(),
  body('theme').isString().isIn(['light', 'dark'])
];

exports.vulnerableUpdateProfile = (req, res) => {
  const profile = {}
  Object.assign(profile, req.body)

  fs.writeFileSync("./data.json", JSON.stringify(profile))
  const ffmpegArgs = [
    '-i', "./img/image.jpg",
    '-vf', `scale=${300}:${300}`,
    '-f', 'image2pipe',
    '-vcodec', 'png',
    '-'
  ];

  const ffmpegProcess = spawn('ffmpeg', ffmpegArgs);
  ffmpegProcess.stdout.pipe(res);

  ffmpegProcess.on('close', () => {
    res.end();
  });

  ffmpegProcess.on('error', (err) => {
    console.error(`Error: ${err.message}`);
    res.status(500).json({ error: 'Image processing failed' });
  });  
  res.send(204);
};