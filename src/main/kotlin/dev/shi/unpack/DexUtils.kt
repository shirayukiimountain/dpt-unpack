package dev.shi.unpack

import org.jf.dexlib2.DexFileFactory
import org.jf.dexlib2.Opcodes
import org.jf.dexlib2.iface.ClassDef
import org.jf.dexlib2.iface.Method
import org.jf.dexlib2.iface.instruction.Instruction
import org.jf.dexlib2.iface.reference.MethodReference
import org.jf.dexlib2.immutable.ImmutableClassDef
import org.jf.dexlib2.immutable.ImmutableDexFile
import org.jf.dexlib2.immutable.ImmutableMethod
import org.jf.dexlib2.immutable.ImmutableMethodImplementation
import java.io.File

object DexUtils {

    fun removeClinitJniBridgeCall(dexFile: File, jniClsName: String? = null) {
        if (!dexFile.exists()) return

        val loadedDexFile = runCatching {
            DexFileFactory.loadDexFile(dexFile, Opcodes.getDefault())
        }.getOrElse {
            DexFileFactory.loadDexFile(dexFile, Opcodes.forApi(19))
        }

        val newClasses = mutableListOf<ClassDef>()
        var modified = false
        var removedCount = 0

        val jniClsSig = jniClsName?.replace('.', '/')

        for (classDef in loadedDexFile.classes) {
            var newMethods: MutableList<Method>? = null
            for ((index, method) in classDef.methods.withIndex()) {
                if (method.name == "<clinit>") {
                    val implementation = method.implementation
                    if (implementation != null) {
                        val instructions = runCatching { implementation.instructions.toList() }.getOrNull()
                        if (instructions != null) {
                            val newInstructions = instructions.filterNot { isJniBridgeClinitCall(it, jniClsSig) }

                            if (newInstructions.size < instructions.size) {
                                if (newMethods == null) {
                                    newMethods = classDef.methods.toMutableList()
                                }
                                removedCount += (instructions.size - newInstructions.size)

                                val newImplementation = ImmutableMethodImplementation(
                                    implementation.registerCount,
                                    newInstructions,
                                    implementation.tryBlocks,
                                    implementation.debugItems
                                )
                                newMethods[index] = ImmutableMethod(
                                    method.definingClass,
                                    method.name,
                                    method.parameters,
                                    method.returnType,
                                    method.accessFlags,
                                    method.annotations,
                                    method.hiddenApiRestrictions,
                                    newImplementation
                                )
                                modified = true
                            }
                        }
                    }
                }
            }
            if (newMethods != null) {
                newClasses.add(
                    ImmutableClassDef(
                        classDef.type,
                        classDef.accessFlags,
                        classDef.superclass,
                        classDef.interfaces,
                        classDef.sourceFile,
                        classDef.annotations,
                        classDef.fields,
                        newMethods
                    )
                )
            } else {
                newClasses.add(classDef)
            }
        }

        if (modified) {
            val newDexFile = ImmutableDexFile(loadedDexFile.opcodes, newClasses)
            DexFileFactory.writeDexFile(dexFile.absolutePath, newDexFile)
        }

        if (removedCount > 0) {
            println("  - Removed $removedCount JNI bridge calls from ${dexFile.name}")
        }
    }

    private fun isJniBridgeClinitCall(instruction: Instruction, jniClsSig: String?): Boolean {
        if (instruction.opcode.name == "invoke-static") {
            if (instruction is org.jf.dexlib2.iface.instruction.ReferenceInstruction) {
                val ref = instruction.reference
                if (ref is MethodReference) {
                    val defClass = ref.definingClass
                    val isClinitOrInit = ref.name == "clinit" || ref.name == "ia" || ref.name == "cbde"
                    if (isClinitOrInit) {
                        if (defClass.contains("JniBridge")) return true
                        if (jniClsSig != null && defClass.contains(jniClsSig)) return true
                    }
                }
            }
        }
        return false
    }
}
