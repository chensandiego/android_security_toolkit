from androguard.misc import AnalyzeAPK
from androguard.core.apk import APK
from androguard.core.dex import DEX
from androguard.core.analysis.analysis import MethodAnalysis

class TaintAnalyzer:
    def __init__(self):
        self.sources = {
            "Landroid/telephony/TelephonyManager;->getDeviceId()Ljava/lang/String;": "IMEI",
            "Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;": "Intent Data",
            "Landroid/location/Location;->getLatitude()D": "Location Latitude",
            "Landroid/location/Location;->getLongitude()D": "Location Longitude",
            "Landroid/provider/Settings$Secure;->getString(Landroid/content/ContentResolver;Ljava/lang/String;)Ljava/lang/String;": "Android ID"
        }
        self.sinks = {
            "Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I": "Log Output",
            "Ljava/io/PrintStream;->println(Ljava/lang/String;)V": "Console Output",
            "Ljava/net/Socket;->getOutputStream()Ljava/io/OutputStream;": "Network Output",
            "Ljava/net/HttpURLConnection;->getOutputStream()Ljava/io/OutputStream;": "HTTP Network Output",
            "Lorg/apache/http/client/HttpClient;->execute(Lorg/apache/http/client/methods/HttpUriRequest;)Lorg/apache/http/HttpResponse;": "Apache HTTP Client Output",
            "Landroid/telephony/SmsManager;->sendTextMessage(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Landroid/app/PendingIntent;Landroid/app/PendingIntent;)V": "SMS Message Send"
        }
        self.taint_flows = []

    def analyze(self, a, d, dx):
        """
        Performs taint analysis on the given APK objects.
        """
        print(f"Starting taint analysis for {a.get_package()}")

        for method in dx.get_methods():
            self._analyze_method_for_taint(method, dx)

        return self.taint_flows

    def _analyze_method_for_taint(self, method_analysis, dx):
        """
        Analyzes a single method for taint flows using intra-procedural analysis.
        """
        if not method_analysis or method_analysis.is_external():
            return

        # tainted_registers: A set of register names that currently hold tainted data
        tainted_registers = set()

        # Get the instructions for the current method
        instructions = method_analysis.get_instructions()

        for instruction in instructions:
            # Check if the instruction is a call to a source method
            if instruction.get_name().startswith("invoke-"):
                called_method_full_name = instruction.get_string()
                if called_method_full_name in self.sources:
                    # If a source is called, the return value (if any) is tainted
                    # The return value is typically in v0 or v1 depending on type
                    # This is a simplification; actual register allocation is more complex
                    if "return" in instruction.get_output(): # Check if it's a method that returns a value
                        # Assuming return value goes to v0 for simplicity
                        tainted_registers.add("v0")
                        tainted_registers.add("v1") # For double-word returns (long, double)
                    print(f"  [TAINT] Source '{self.sources[called_method_full_name]}' called in {method_analysis.full_name}. Tainting return registers.")

            # Check for data movement instructions (e.g., 'move', 'move-result')
            # This is a very basic propagation. A full implementation would need to parse
            # instruction arguments and types more thoroughly.
            if instruction.get_name().startswith("move") or instruction.get_name().startswith("const"):
                output_registers = instruction.get_output_registers()
                input_registers = instruction.get_input_registers()

                # If an input register is tainted, the output register becomes tainted
                for in_reg in input_registers:
                    if in_reg in tainted_registers:
                        for out_reg in output_registers:
                            tainted_registers.add(out_reg)
                            print(f"  [TAINT] Propagating taint from {in_reg} to {out_reg} via {instruction.get_name()} in {method_analysis.full_name}.")

            # Check if the instruction is a call to a sink method
            if instruction.get_name().startswith("invoke-"):
                called_method_full_name = instruction.get_string()
                if called_method_full_name in self.sinks:
                    # Check if any of the arguments passed to the sink are tainted
                    # This is a simplification; need to map instruction arguments to registers
                    # For now, we'll assume if any register is tainted, and a sink is called,
                    # it's a potential flow.
                    # A more precise check would involve mapping arguments to specific registers
                    # and checking if those specific argument registers are tainted.
                    
                    # Get the arguments passed to the method call
                    # Androguard's instruction.get_operands() can give us this, but parsing
                    # them to actual register names requires more logic.
                    # For this simplified version, we'll just check if *any* currently tainted
                    # register is involved in the call (which is still very broad).

                    # A better approach would be to analyze the instruction's arguments
                    # and see if any of the registers used as arguments are tainted.
                    # For example, for 'invoke-virtual {v0, v1}, Lcom/example/MyClass;->mySink(Ljava/lang/String;)V'
                    # we'd check if v0 or v1 are tainted.

                    # For now, a very basic check:
                    if tainted_registers:
                        flow = {
                            "source": "Unknown (intra-procedural)", # Source is within this method
                            "source_description": "Tainted data detected",
                            "sink": called_method_full_name,
                            "sink_description": self.sinks[called_method_full_name],
                            "method_path": method_analysis.full_name,
                            "instruction": instruction.get_name() + " " + instruction.get_output()
                        }
                        self.taint_flows.append(flow)
                        print(f"  [TAINT] Potential taint flow detected: {self.sinks[called_method_full_name]} in {method_analysis.full_name} at instruction {instruction.get_name()}.")

if __name__ == '__main__':
    # Example usage (replace with a real APK path for testing)
    # For testing, you might want to use a small, known APK.
    # apk_file = "/path/to/your/app.apk"
    # analyzer = TaintAnalyzer()
    # flows = analyzer.analyze_apk(apk_file)
    # if flows:
    #     print("\nDetected Taint Flows:")
    #     for flow in flows:
    #         print(f"- Source: {flow['source_description']} ({flow['source']})")
    #         print(f"  Sink: {flow['sink_description']} ({flow['sink']})")
    #         print(f"  Method: {flow['method_path']}")
    #         print(f"  Instruction: {flow['instruction']}")
    # else:
    #     print("\nNo taint flows detected.")
    pass