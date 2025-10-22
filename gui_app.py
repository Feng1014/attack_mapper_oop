from __future__ import annotations
import sys
from typing import Optional, Type

from PyQt5 import QtWidgets, QtCore
import os


class MappingGuiApp:
    """
    将 UI 封装为一个独立的 class。接收一个 Pipeline 类（而不是实例），
    便于在 UI 层创建新实例，避免跨线程/状态问题。
    """

    def __init__(self, pipeline_cls: Type):
        self.pipeline_cls = pipeline_cls

    def run(self):
        app = QtWidgets.QApplication(sys.argv)
        w = self.MainWindow(self.pipeline_cls)
        w.show()
        sys.exit(app.exec_())

    class MainWindow(QtWidgets.QWidget):
        def __init__(self, pipeline_cls: Type):
            super().__init__()
            self.setWindowTitle("国能态感转换与映射（含 ATT&CK 分类） - OOP")
            self.setMinimumWidth(820)

            self.pipeline = pipeline_cls()  # 在 UI 中持有一个 pipeline 实例

            self.json_path: Optional[str] = None
            self.tpl_path: Optional[str] = None

            LEFT_COL_WIDTH = 160

            self.btn_pick_json = QtWidgets.QPushButton("读取（选择 JSON）")
            self.btn_pick_json.setFixedWidth(LEFT_COL_WIDTH)
            self.le_json = QtWidgets.QLineEdit()
            self.le_json.setReadOnly(True)

            self.btn_pick_tpl = QtWidgets.QPushButton("映射（选择模板Excel）")
            self.btn_pick_tpl.setFixedWidth(LEFT_COL_WIDTH)
            self.le_tpl = QtWidgets.QLineEdit()
            self.le_tpl.setReadOnly(True)

            self.btn_sheet_label = QtWidgets.QPushButton("工作表名（可选）")
            self.btn_sheet_label.setEnabled(False)
            self.btn_sheet_label.setFixedWidth(LEFT_COL_WIDTH)
            self.le_sheet = QtWidgets.QLineEdit()
            self.le_sheet.setPlaceholderText("不填则使用模板的首个工作表")

            self.btn_convert = QtWidgets.QPushButton("转换（备份并写回）")
            self.btn_convert.setEnabled(False)
            self.btn_export_log = QtWidgets.QPushButton("导出日志到文件")

            self.btn_convert_alarm = QtWidgets.QPushButton("映射成测试json")
            self.btn_convert_alarm.setEnabled(False)
            self.btn_convert_alarm.setToolTip("把上方选择的 JSON 映射为 *.alarm.json")

            self.log_box = QtWidgets.QTextEdit()
            self.log_box.setReadOnly(True)
            self.log_box.setPlaceholderText("日志输出...")

            layout = QtWidgets.QVBoxLayout(self)

            row1 = QtWidgets.QHBoxLayout()
            row1.addWidget(self.btn_pick_json, 0)
            row1.addWidget(self.le_json, 1)
            layout.addLayout(row1)

            row2 = QtWidgets.QHBoxLayout()
            row2.addWidget(self.btn_pick_tpl, 0)
            row2.addWidget(self.le_tpl, 1)
            layout.addLayout(row2)

            row3 = QtWidgets.QHBoxLayout()
            row3.addWidget(self.btn_sheet_label, 0)
            row3.addWidget(self.le_sheet, 1)
            layout.addLayout(row3)

            row4 = QtWidgets.QHBoxLayout()
            self.btn_convert.setSizePolicy(
                QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Fixed)
            self.btn_export_log.setSizePolicy(
                QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Fixed)
            row4.addWidget(self.btn_convert, 1)
            row4.addWidget(self.btn_export_log, 1)
            self.btn_convert_alarm.setSizePolicy(
                QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Fixed)
            row4.addWidget(self.btn_convert_alarm, 1)
            layout.addLayout(row4)

            layout.addWidget(self.log_box, 1)

            self.btn_pick_json.clicked.connect(self.pick_json)
            self.btn_pick_tpl.clicked.connect(self.pick_tpl)
            self.btn_convert.clicked.connect(self.do_convert)
            self.btn_export_log.clicked.connect(self.export_log)
            self.btn_convert_alarm.clicked.connect(self.on_convert_alarm_json)

        def log(self, msg: str):
            self.log_box.append(msg)
            print(msg)

        def pick_json(self):
            path, _ = QtWidgets.QFileDialog.getOpenFileName(
                self, "选择 JSON 文件", "", "JSON (*.json);;所有文件 (*)")
            if path:
                self.json_path = path
                self.le_json.setText(path)
                self.log(f"[INFO] 已选择 JSON：{path}")
                self.update_convert_enabled()

        def pick_tpl(self):
            path, _ = QtWidgets.QFileDialog.getOpenFileName(
                self, "选择模板 Excel（第二行英文表头）", "", "Excel 文件 (*.xlsx);;所有文件 (*)")
            if path:
                self.tpl_path = path
                self.le_tpl.setText(path)
                self.log(f"[INFO] 已选择模板：{path}")
                self.update_convert_enabled()

        def update_convert_enabled(self):
            ok_excel = bool(self.json_path) and bool(self.tpl_path)
            self.btn_convert.setEnabled(ok_excel)
            # 仅选择了 JSON 也可启用“映射成测试json”
            self.btn_convert_alarm.setEnabled(bool(self.json_path))
            if ok_excel:
                self.log("[INFO] 条件满足，可进行模板映射。")

        def do_convert(self):
            if not (self.json_path and self.tpl_path):
                QtWidgets.QMessageBox.warning(self, "提示", "请先选择 JSON 与 模板文件。")
                return
            try:
                self.setEnabled(False)
                QtWidgets.QApplication.setOverrideCursor(QtCore.Qt.WaitCursor)
                self.log("[RUN] 开始解析 JSON 并执行映射写回...]")

                rows_written, cols_mapped, backup_path = self.pipeline.process_to_template(
                    json_path=self.json_path,
                    template_path=self.tpl_path,
                    sheet_name=(self.le_sheet.text().strip() or None)
                )

                if backup_path:
                    self.log(f"[OK] 覆盖模板前已备份：{backup_path}")
                self.log(
                    f"[OK] 已写入：{rows_written} 行 / {cols_mapped} 列 → {self.tpl_path}")
                QtWidgets.QMessageBox.information(
                    self, "完成", "转换与映射完成（含 ATT&CK 分类）。")

            except Exception as e:
                self.log(f"[ERROR] 转换失败：{e}")
                QtWidgets.QMessageBox.critical(self, "错误", f"转换失败：\n{e}")
            finally:
                QtWidgets.QApplication.restoreOverrideCursor()
                self.setEnabled(True)

        def export_log(self):
            path, _ = QtWidgets.QFileDialog.getSaveFileName(
                self, "保存日志到文件", "转换日志.txt", "文本文件 (*.txt);;所有文件 (*)")
            if not path:
                return
            try:
                with open(path, "w", encoding="utf-8") as f:
                    f.write(self.log_box.toPlainText())
                self.log(f"[OK] 日志已导出：{path}")
            except Exception as e:
                self.log(f"[ERROR] 日志导出失败：{e}")

        # 把“读取（选择 JSON）”得到的路径直接映射为 *.alarm.json
        def on_convert_alarm_json(self):
            if not self.json_path:
                QtWidgets.QMessageBox.warning(self, "提示", "请先点击“读取（选择 JSON）”。")
                return
            try:
                # 目标路径 = 源 JSON 同目录同名 + '.alarm.json'
                base, _ = os.path.splitext(self.json_path)
                out_path = base + ".alarm.json"

                QtWidgets.QApplication.setOverrideCursor(QtCore.Qt.WaitCursor)
                self.setEnabled(False)
                self.log(f"[RUN] 生成测试 JSON：{self.json_path} -> {out_path}")

                # 使用 Pipeline 的导出逻辑；不再弹出文件选择或再次读取原始 JSON
                written = self.pipeline.export_alarm_json(
                    self.json_path, out_path)
                self.log(f"[OK] 已生成：{written}")
                QtWidgets.QMessageBox.information(
                    self, "完成", f"新 JSON 已生成，并保存在源文件同目录：\n{written}")
            except Exception as e:
                self.log(f"[ERROR] 生成失败：{e}")
                QtWidgets.QMessageBox.critical(self, "错误", f"生成失败：\n{e}")
            finally:
                QtWidgets.QApplication.restoreOverrideCursor()
                self.setEnabled(True)
