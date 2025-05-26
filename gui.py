import sys
import os
import argparse
import traceback
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QTabWidget,
    QVBoxLayout, QHBoxLayout, QFormLayout, QGroupBox,
    QCheckBox, QComboBox, QLineEdit, QPushButton, QFileDialog,
    QSpinBox, QDoubleSpinBox, QMessageBox, QLabel,
    QRadioButton, QGraphicsView, QGraphicsScene, QRubberBand, QSizePolicy
)
from PySide6.QtCore import Qt, QRectF, QSize, QPoint, QRect
from PySide6.QtGui import QPixmap, QPen, QColor

import anonymizer
import pixelate_statter


class ZoomableView(QGraphicsView):
    def __init__(self, roi_callback, parent=None):
        super().__init__(parent)
        self._rubber = QRubberBand(QRubberBand.Rectangle, self.viewport())
        self._rect_item = None
        self._origin = None
        self._roi_callback = roi_callback

        # для ручного панинга
        self._panning = False
        self._pan_start = QPoint()
        self._hbar_start = 0
        self._vbar_start = 0

        self.setTransformationAnchor(QGraphicsView.AnchorUnderMouse)
        self.setResizeAnchor(QGraphicsView.AnchorUnderMouse)
        self.setDragMode(QGraphicsView.NoDrag)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOn)
        self.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOn)

    def wheelEvent(self, ev):
        factor = 1.2 if ev.angleDelta().y() > 0 else 1/1.2
        self.scale(factor, factor)

    def mousePressEvent(self, ev):
        if ev.button() == Qt.LeftButton:
            # ROI rubber-band
            self._origin = ev.pos()
            self._rubber.setGeometry(QRect(self._origin, QSize()))
            self._rubber.show()
        elif ev.button() == Qt.RightButton:
            # начать панинг
            self._panning = True
            self._pan_start = ev.pos()
            self._hbar_start = self.horizontalScrollBar().value()
            self._vbar_start = self.verticalScrollBar().value()
            self.setCursor(Qt.ClosedHandCursor)
        else:
            super().mousePressEvent(ev)

    def mouseMoveEvent(self, ev):
        if self._rubber.isVisible():
            self._rubber.setGeometry(QRect(self._origin, ev.pos()).normalized())
        elif self._panning:
            # вычисляем смещение и прокручиваем
            delta = ev.pos() - self._pan_start
            self.horizontalScrollBar().setValue(self._hbar_start - delta.x())
            self.verticalScrollBar().setValue(self._vbar_start - delta.y())
        else:
            super().mouseMoveEvent(ev)

    def mouseReleaseEvent(self, ev):
        if ev.button() == Qt.LeftButton and self._rubber.isVisible():
            self._rubber.hide()
            rect = self._rubber.geometry()
            p1 = self.mapToScene(rect.topLeft())
            p2 = self.mapToScene(rect.bottomRight())
            scene_rect = QRectF(p1, p2).normalized()
            if self._rect_item:
                self.scene().removeItem(self._rect_item)
            pen = QPen(QColor(255, 0, 0))
            pen.setWidth(2)
            self._rect_item = self.scene().addRect(scene_rect, pen)
            self._roi_callback(scene_rect)
        elif ev.button() == Qt.RightButton and self._panning:
            # завершить панинг
            self._panning = False
            self.setCursor(Qt.ArrowCursor)
        else:
            super().mouseReleaseEvent(ev)


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("AnonIt")
        self.resize(800, 600)
        self._roi_scene = None

        tabs = QTabWidget()
        tabs.addTab(self._anonym_tab(), "Анонимизация")
        tabs.addTab(self._deanon_tab(), "Деанонимизация")
        self.setCentralWidget(tabs)

    def _anonym_tab(self):
        w = QWidget()
        ly = QVBoxLayout(w)

        form = QFormLayout()
        self.in_le = QLineEdit()
        b1 = QPushButton("Выбрать файл…"); b1.clicked.connect(self._on_browse_image)
        h1 = QHBoxLayout(); h1.addWidget(self.in_le); h1.addWidget(b1)
        form.addRow("Файл:", h1)

        self.method_cb = QComboBox()
        self.methods = [
            "Маскирование",
            "Псевдонимизация",
            "Шифрование",
            "Шифрование хаотическим методом",
            "Самореконструирующая стеганография"
        ]
        self.method_cb.addItems(self.methods)
        self.method_cb.currentTextChanged.connect(self._upd_params)
        form.addRow("Метод:", self.method_cb)

        self.sens_group = QGroupBox("Чувствительные данные")
        sl = QHBoxLayout(); self.sens_data = {}
        for key, label in [("fio","ФИО"),("phone","Телефон"),
                           ("passport","Паспорт"),("address","Адрес"),("email","Email")]:
            cb = QCheckBox(label); cb.setChecked(True)
            sl.addWidget(cb); self.sens_data[key] = cb
        self.sens_group.setLayout(sl)
        form.addRow(self.sens_group)

        self.lang_label = QLabel("Язык данных:")
        self.lang_cb    = QComboBox(); self.lang_cb.addItems(["ru","en"])
        form.addRow(self.lang_label, self.lang_cb)

        ly.addLayout(form)

        self.params_w = QWidget(); self.pform = QFormLayout(self.params_w)
        ly.addWidget(self.params_w)

        # Preview + ROI
        self.view  = ZoomableView(self.set_roi, parent=self)
        self.scene = QGraphicsScene(self.view)
        self.view.setScene(self.scene)
        self.view.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        ly.addWidget(self.view)

        self.out_le = QLineEdit()
        b2 = QPushButton("Сохранить в…"); b2.clicked.connect(lambda: self._browse(self.out_le, True))
        h2 = QHBoxLayout(); h2.addWidget(self.out_le); h2.addWidget(b2)
        ly.addLayout(h2)

        run = QPushButton("Запустить"); run.clicked.connect(self._run_anonym)
        ly.addWidget(run, alignment=Qt.AlignRight)

        self._upd_params(self.methods[0])
        return w

    def _deanon_tab(self):
        w = QWidget(); ly = QVBoxLayout(w)
        form = QFormLayout()
        self.din_le = QLineEdit()
        b1 = QPushButton("Выбрать файл…"); b1.clicked.connect(lambda: self._browse(self.din_le))
        h1 = QHBoxLayout(); h1.addWidget(self.din_le); h1.addWidget(b1)
        form.addRow("Аноним файл:", h1)
        self.method2_cb = QComboBox(); self.method2_cb.addItems(self.methods)
        self.method2_cb.currentTextChanged.connect(self._upd_params2)
        form.addRow("Метод:", self.method2_cb)
        ly.addLayout(form)

        self.params2_w = QWidget(); self.pform2 = QFormLayout(self.params2_w)
        ly.addWidget(self.params2_w)

        self.dout_le = QLineEdit()
        b2 = QPushButton("Сохранить в…"); b2.clicked.connect(lambda: self._browse(self.dout_le, True))
        h2 = QHBoxLayout(); h2.addWidget(self.dout_le); h2.addWidget(b2)
        ly.addLayout(h2)

        run = QPushButton("Восстановить"); run.clicked.connect(self._run_deanon)
        ly.addWidget(run, alignment=Qt.AlignRight)

        self._upd_params2(self.methods[0])
        return w

    def _on_browse_image(self):
        self._browse(self.in_le, save=False)
        path = self.in_le.text().strip()
        ext  = os.path.splitext(path)[1].lower()
        if ext in ('.png','.jpg','.jpeg','.bmp'):
            pix = QPixmap(path)
            self.scene.clear()
            item = self.scene.addPixmap(pix)
            rect = item.boundingRect()
            self.scene.setSceneRect(rect)
            self.view.fitInView(rect, Qt.KeepAspectRatio)
            self._roi_scene = None
            b, e = os.path.splitext(path)
            self.out_le.setText(f"{b}_anon{e}")

    def set_roi(self, scene_rect: QRectF):
        self._roi_scene = scene_rect

    def _browse(self, le, save=False):
        if save:
            p,_ = QFileDialog.getSaveFileName(self, "Сохранить файл", os.getcwd())
        else:
            p,_ = QFileDialog.getOpenFileName(self, "Выбрать файл", os.getcwd())
        if p:
            le.setText(p)

    def _clear(self, lyt):
        while lyt.count():
            w = lyt.takeAt(0).widget()
            if w:
                w.deleteLater()

    def _upd_params(self, m):
        text_methods = ["Маскирование","Псевдонимизация","Шифрование хаотическим методом"]
        is_stego = (m == "Самореконструирующая стеганография")

        self.sens_group.setVisible(m in text_methods)
        self.lang_label.setVisible(m in text_methods)
        self.lang_cb.setVisible(m in text_methods)
        self.view.setVisible(is_stego)

        self._clear(self.pform)
        max_int = 2**31 - 1

        if m == "Псевдонимизация":
            sb = QSpinBox(); sb.setRange(0, max_int)
            self.pform.addRow(f"Seed (0–{max_int}):", sb); self.spin_p = sb

        elif m == "Шифрование хаотическим методом":
            x0 = QDoubleSpinBox(); x0.setRange(0.0001,0.9999); x0.setValue(0.5)
            r  = QDoubleSpinBox(); r.setRange(0.0,4.0);      r.setValue(3.99)
            self.pform.addRow("Seed x0:", x0); self.spin_x0 = x0
            self.pform.addRow("Param r:",  r ); self.spin_r  = r

        elif is_stego:
            pix      = QSpinBox(); pix.setRange(1,100); pix.setValue(10)
            q        = QSpinBox(); q.setRange(1,100);   q.setValue(30)
            rb1      = QRadioButton("Пикселизация"); rb2 = QRadioButton("Шумирование")
            rb1.setChecked(True)
            noise_sb = QDoubleSpinBox(); noise_sb.setRange(0,100); noise_sb.setValue(50)
            self.pform.addRow("Pixel size:",       pix);        self.spin_pix   = pix
            self.pform.addRow("JPEG quality:",     q);          self.spin_q     = q
            self.pform.addRow("Режим:",            rb1);        self.pform.addRow("", rb2)
            self.pform.addRow("Уровень шума (%):", noise_sb);  self.spin_noise = noise_sb
            self.rb_pixel, self.rb_noise = rb1, rb2

        self.params_w.setVisible(self.pform.count() > 0)

    def _upd_params2(self, m):
        self._clear(self.pform2)
        max_int = 2**31 - 1

        if m == "Псевдонимизация":
            sb = QSpinBox(); sb.setRange(0, max_int)
            self.pform2.addRow(f"Seed (0–{max_int}):", sb); self.p2 = sb

        elif m == "Шифрование хаотическим методом":
            x0 = QDoubleSpinBox(); x0.setRange(0.0001,0.9999); x0.setValue(0.5)
            r  = QDoubleSpinBox(); r.setRange(0.0,4.0);      r.setValue(3.99)
            self.pform2.addRow("Seed x0:", x0); self.x02 = x0
            self.pform2.addRow("Param r:",  r ); self.r2  = r

        self.params2_w.setVisible(self.pform2.count() > 0)

    def _run_anonym(self):
        inf   = self.in_le.text().strip()
        outf  = self.out_le.text().strip()
        m     = self.method_cb.currentText()
        types = [k for k, cb in self.sens_data.items() if cb.isChecked()]
        lang  = self.lang_cb.currentText()

        try:
            if m == "Самореконструирующая стеганография":
                mode_ext = 'pixelate' if self.rb_pixel.isChecked() else 'noise'
                rect = self._roi_scene or QRectF(0,0,0,0)
                x,y,w,h = int(rect.x()), int(rect.y()), int(rect.width()), int(rect.height())
                args = argparse.Namespace(
                    mode='anonymize', image=inf, output=outf,
                    pixel_size=self.spin_pix.value(),
                    quality=self.spin_q.value(),
                    mode_ext=mode_ext,
                    noise_level=self.spin_noise.value(),
                    x=x, y=y, w=w, h=h
                )
                pixelate_statter.anonymize(args)
            else:
                method_map = {
                    "Маскирование": "mask",
                    "Псевдонимизация": "pseudonymize",
                    "Шифрование": "encrypt",
                    "Шифрование хаотическим методом": "chaos"
                }
                kwargs = {}
                if m == "Псевдонимизация":
                    kwargs["pseudo_seed"] = self.spin_p.value()
                if m == "Шифрование хаотическим методом":
                    kwargs["chaos_seed"] = self.spin_x0.value()
                    kwargs["chaos_r"]    = self.spin_r.value()

                anonymizer.anonymize_file(
                    inf,
                    method_map[m],
                    categories=types,
                    lang=lang,
                    **kwargs
                )

            b,e = os.path.splitext(inf)
            d   = f"{b}_anon{e}"
            if d != outf and os.path.exists(d):
                os.replace(d, outf)
            QMessageBox.information(self, "Успех", "Готово")
        except Exception:
            QMessageBox.critical(self, "Ошибка при анонимизации", traceback.format_exc())

    def _run_deanon(self):
        inf   = self.din_le.text().strip()
        outf  = self.dout_le.text().strip()
        m     = self.method2_cb.currentText()

        try:
            if m in ("Маскирование", "Псевдонимизация", "Шифрование", "Шифрование хаотическим методом"):
                anonymizer.deanonymize_file(inf)
            else:
                args = argparse.Namespace(mode='restore', image=inf, output=outf)
                pixelate_statter.restore(args)

            b,e = os.path.splitext(inf)
            d   = f"{b}_restored{e}"
            if d != outf and os.path.exists(d):
                os.replace(d, outf)
            QMessageBox.information(self, "Успех", "Готово")
        except Exception:
            QMessageBox.critical(self, "Ошибка при деанонимизаци", traceback.format_exc())


if __name__ == '__main__':
    app = QApplication(sys.argv)
    MainWindow().show()
    sys.exit(app.exec())
