import sys
import os
import argparse
import traceback
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QTabWidget,
    QVBoxLayout, QHBoxLayout, QFormLayout,
    QLineEdit, QPushButton, QFileDialog,
    QComboBox, QSpinBox, QDoubleSpinBox, QMessageBox
)
from PySide6.QtCore import Qt

import anonymizer
import pixelate_statter

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("AnonIt")
        self.resize(600,400)
        tabs = QTabWidget()
        tabs.addTab(self._anonym_tab(),   "Анонимизация")
        tabs.addTab(self._deanon_tab(),   "Деанонимизация")
        self.setCentralWidget(tabs)

    def _anonym_tab(self):
        w=QWidget(); ly=QVBoxLayout(w); form=QFormLayout()
        # вход
        self.in_le=QLineEdit()
        b1=QPushButton("Выбрать файл…"); b1.clicked.connect(lambda:self._browse(self.in_le))
        r1=QHBoxLayout(); r1.addWidget(self.in_le); r1.addWidget(b1)
        form.addRow("Файл:",r1)
        # метод
        self.method_cb=QComboBox()
        self.methods=["Маскирование","Псевдонимизация",
                      "Шифрование","Шифрование хаотическим методом",
                      "Стеганография с пикселизацией"]
        self.method_cb.addItems(self.methods)
        self.method_cb.currentTextChanged.connect(self._upd_params)
        form.addRow("Метод:",self.method_cb)
        ly.addLayout(form)
        # параметры
        self.params_w=QWidget(); self.pform=QFormLayout(self.params_w)
        ly.addWidget(self.params_w)
        # выход
        self.out_le=QLineEdit()
        b2=QPushButton("Сохранить в…"); b2.clicked.connect(lambda:self._browse(self.out_le,True))
        r2=QHBoxLayout(); r2.addWidget(self.out_le); r2.addWidget(b2)
        ly.addLayout(r2)
        # запуск
        run=QPushButton("Запустить"); run.clicked.connect(self._run_anonym)
        ly.addWidget(run,alignment=Qt.AlignRight)
        self._upd_params(self.method_cb.currentText())
        return w

    def _deanon_tab(self):
        w=QWidget(); ly=QVBoxLayout(w); form=QFormLayout()
        self.din_le=QLineEdit()
        b1=QPushButton("Выбрать файл…"); b1.clicked.connect(lambda:self._browse(self.din_le))
        r1=QHBoxLayout(); r1.addWidget(self.din_le); r1.addWidget(b1)
        form.addRow("Аноним файл:",r1)
        self.method2_cb=QComboBox(); self.method2_cb.addItems(self.methods)
        self.method2_cb.currentTextChanged.connect(self._upd_params2)
        form.addRow("Метод:",self.method2_cb)
        ly.addLayout(form)
        self.params2_w=QWidget(); self.pform2=QFormLayout(self.params2_w)
        ly.addWidget(self.params2_w)
        self.dout_le=QLineEdit()
        b2=QPushButton("Сохранить в…"); b2.clicked.connect(lambda:self._browse(self.dout_le,True))
        r2=QHBoxLayout(); r2.addWidget(self.dout_le); r2.addWidget(b2)
        ly.addLayout(r2)
        run=QPushButton("Восстановить"); run.clicked.connect(self._run_deanon)
        ly.addWidget(run,alignment=Qt.AlignRight)
        self._upd_params2(self.method2_cb.currentText())
        return w

    def _browse(self,le,save=False):
        if save:
            p,_=QFileDialog.getSaveFileName(self,"Сохранить файл",os.getcwd())
        else:
            p,_=QFileDialog.getOpenFileName(self,"Выбрать файл",os.getcwd())
        if not p: return
        le.setText(p)
        if not save:
            b,e=os.path.splitext(p)
            if le is self.in_le:   self.out_le.setText(f"{b}_anon{e}")
            if le is self.din_le:   self.dout_le.setText(f"{b}_restored{e}")

    def _clear(self,lyt):
        while lyt.count():
            w=lyt.takeAt(0).widget()
            if w: w.deleteLater()

    def _upd_params(self,m):
        self._clear(self.pform)
        max_int=2**31-1
        if m=="Псевдонимизация":
            sb=QSpinBox(); sb.setRange(0,max_int)
            self.pform.addRow(f"Seed (0–{max_int}):",sb); self.spin_p=sb
        elif m=="Шифрование хаотическим методом":
            x0=QDoubleSpinBox(); x0.setRange(0.0001,0.9999)
            x0.setSingleStep(0.01); x0.setValue(0.5)
            self.pform.addRow("Seed x0:",x0); self.spin_x0=x0
            r=QDoubleSpinBox(); r.setRange(0.0,4.0)
            r.setSingleStep(0.01); r.setValue(3.99)
            self.pform.addRow("Param r:",r); self.spin_r=r
        elif m=="Стеганография с пикселизацией":
            pix=QSpinBox(); pix.setRange(1,100); pix.setValue(10)
            self.pform.addRow("Pixel size:",pix); self.spin_pix=pix
            q=QSpinBox(); q.setRange(1,100);   q.setValue(30)
            self.pform.addRow("JPEG quality:",q); self.spin_q=q
        self.params_w.setVisible(self.pform.count()>0)

    def _upd_params2(self,m):
        self._clear(self.pform2)
        max_int=2**31-1
        if m=="Псевдонимизация":
            sb=QSpinBox(); sb.setRange(0,max_int)
            self.pform2.addRow(f"Seed (0–{max_int}):",sb); self.p2=sb
        elif m=="Шифрование хаотическим методом":
            x0=QDoubleSpinBox(); x0.setRange(0.0001,0.9999)
            x0.setSingleStep(0.01); x0.setValue(0.5)
            self.pform2.addRow("Seed x0:",x0); self.x02=x0
            r=QDoubleSpinBox(); r.setRange(0.0,4.0)
            r.setSingleStep(0.01); r.setValue(3.99)
            self.pform2.addRow("Param r:",r); self.r2=r
        self.params2_w.setVisible(self.pform2.count()>0)

    def _run_anonym(self):
        inf=self.in_le.text().strip(); outf=self.out_le.text().strip()
        m=self.method_cb.currentText()
        try:
            if m=="Маскирование":
                anonymizer.anonymize_file(inf,'mask')
            elif m=="Псевдонимизация":
                anonymizer.anonymize_file(inf,'pseudonymize',pseudo_seed=self.spin_p.value())
            elif m=="Шифрование":
                anonymizer.anonymize_file(inf,'encrypt')
            elif m=="Шифрование хаотическим методом":
                anonymizer.anonymize_file(inf,'chaos',
                                         chaos_seed=self.spin_x0.value(),
                                         chaos_r=self.spin_r.value())
            else:
                args=argparse.Namespace(mode='anonymize',
                                        image=inf,output=outf,
                                        pixel_size=self.spin_pix.value(),
                                        quality=self.spin_q.value())
                pixelate_statter.anonymize(args)
            b,e=os.path.splitext(inf); d=f"{b}_anon{e}"
            if d!=outf and os.path.exists(d): os.replace(d,outf)
            QMessageBox.information(self,"Успех","Готово")
        except Exception:
            tb=traceback.format_exc()
            QMessageBox.critical(self,"Ошибка при анонимизации",tb)

    def _run_deanon(self):
        inf=self.din_le.text().strip(); outf=self.dout_le.text().strip()
        m=self.method2_cb.currentText()
        try:
            if m in ("Маскирование","Псевдонимизация","Шифрование","Шифрование хаотическим методом"):
                anonymizer.deanonymize_file(inf)
            else:
                args=argparse.Namespace(mode='restore',image=inf,output=outf)
                pixelate_statter.restore(args)
            b,e=os.path.splitext(inf); d=f"{b}_restored{e}"
            if d!=outf and os.path.exists(d): os.replace(d,outf)
            QMessageBox.information(self,"Успех","Готово")
        except Exception:
            tb=traceback.format_exc()
            QMessageBox.critical(self,"Ошибка при деанонимизации",tb)

if __name__=='__main__':
    app=QApplication(sys.argv)
    MainWindow().show()
    sys.exit(app.exec())
