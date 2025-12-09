// sign-pdf.js (abridged)
const express = require('express');
const { PDFDocument } = require('pdf-lib');
const crypto = require('crypto');
const fs = require('fs');
const mongodb = require('mongodb');
const app = express();
app.use(express.json({ limit: '20mb' })); // signature images can be base64

// mongodb setup (example)
const MongoClient = mongodb.MongoClient;
const mongoUrl = "mongodb://localhost:27017";
let db;
MongoClient.connect(mongoUrl, { useUnifiedTopology: true }).then(client => {
  db = client.db('signature_demo');
});

function sha256(buffer) {
  return crypto.createHash('sha256').update(buffer).digest('hex');
}

app.post('/sign-pdf', async (req, res) => {
  try {
    const { pdfId, signature, fields } = req.body;
    // load original PDF - for prototype we'll read from disk
    const originalPdfPath = `./pdfs/${pdfId}.pdf`;
    const origBytes = fs.readFileSync(originalPdfPath);
    const origHash = sha256(origBytes);

    // load PDF with pdf-lib
    const pdfDoc = await PDFDocument.load(origBytes);
    const pages = pdfDoc.getPages();

    // load signature image bytes
    // signature is "data:image/png;base64,...." or jpg. handle both.
    const base64 = signature.split(',')[1];
    const sigBytes = Buffer.from(base64, 'base64');

    // Decide image type
    let embeddedImage;
    let imgDims = { width: 0, height: 0 };
    // png
    try {
      embeddedImage = await pdfDoc.embedPng(sigBytes);
      imgDims = embeddedImage.scale(1);
    } catch (e) {
      embeddedImage = await pdfDoc.embedJpg(sigBytes);
      imgDims = embeddedImage.scale(1);
    }
    const imgWidthPx = imgDims.width;
    const imgHeightPx = imgDims.height;
    const imgRatio = imgWidthPx / imgHeightPx;

    // For each field that is type 'signature', place image on the specified page
    for (const f of fields) {
      const pageIndex = f.page - 1;
      const page = pages[pageIndex];
      const { width: pdfW, height: pdfH } = page.getSize();

      // Convert percentages to points
      const x_pts = f.leftPct * pdfW;
      const w_pts = f.widthPct * pdfW;
      const h_pts = f.heightPct * pdfH;
      const y_pts = pdfH * (1 - (f.topPct + f.heightPct)); // bottom-left y

      // Fit image inside box preserving aspect ratio
      const boxRatio = w_pts / h_pts;
      let drawW = w_pts;
      let drawH = h_pts;

      if (imgRatio > boxRatio) {
        // image is wider -> fit width
        drawW = w_pts;
        drawH = w_pts / imgRatio;
      } else {
        // image is taller -> fit height
        drawH = h_pts;
        drawW = h_pts * imgRatio;
      }

      // center inside box
      const offsetX = x_pts + (w_pts - drawW) / 2;
      const offsetY = y_pts + (h_pts - drawH) / 2;

      // Do not distort: draw image using computed drawW/drawH
      page.drawImage(embeddedImage, {
        x: offsetX,
        y: offsetY,
        width: drawW,
        height: drawH,
      });
    }

    const modifiedPdfBytes = await pdfDoc.save();

    // compute post-sign hash
    const postHash = sha256(modifiedPdfBytes);

    // write to disk (prototype)
    const outPath = `./signed/${pdfId}-signed-${Date.now()}.pdf`;
    fs.writeFileSync(outPath, modifiedPdfBytes);

    // store audit record in Mongo
    await db.collection('audit').insertOne({
      pdfId,
      originalHash: origHash,
      signedHash: postHash,
      signedAt: new Date(),
      fields,
      outPath,
    });

    // Return URL (in prototype a file path)
    res.json({
      ok: true,
      url: `/signed-files/${pdfId}-signed-${Date.now()}.pdf`,
      originalHash: origHash,
      signedHash: postHash,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ ok: false, error: err.message });
  }
});

app.listen(3001, ()=> console.log('listening 3001'));
