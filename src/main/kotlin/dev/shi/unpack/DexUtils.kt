package dev.shi.unpack

import org.jf.dexlib2.DexFileFactory
import org.jf.dexlib2.Opcodes
import org.jf.dexlib2.iface.ClassDef
import org.jf.dexlib2.iface.Method
import org.jf.dexlib2.iface.instruction.Instruction
import org.jf.dexlib2.iface.instruction.formats.Instruction35c
import org.jf.dexlib2.iface.reference.MethodReference
import org.jf.dexlib2.immutable.ImmutableClassDef
import org.jf.dexlib2.immutable.ImmutableDexFile
import org.jf.dexlib2.immutable.ImmutableMethod
import org.jf.dexlib2.immutable.ImmutableMethodImplementation
import java.io.File

object DexUtils {

    fun removeClinitJniBridgeCall(dexFile: File) {
        if (!dexFile.exists()) return

        val loadedDexFile = DexFileFactory.loadDexFile(dexFile, Opcodes.forApi(19))
        val newClasses = mutableListOf<ClassDef>()
        var modified = false
        var removedCount = 0

        for (classDef in loadedDexFile.classes) {
            var newMethods: MutableList<Method>? = null
            for ((index, method) in classDef.methods.withIndex()) {
                if (method.name == "<clinit>") {
                    val implementation = method.implementation
                    if (implementation != null) {
                        val instructions = implementation.instructions.toList()
                        val newInstructions = instructions.filterNot { isJniBridgeClinitCall(it) }

                        if (newInstructions.size < instructions.size) {
                            if (newMethods == null) {
                                newMethods = classDef.methods.toMutableList()
                            }
                            removedCount += (instructions.size - newInstructions.size) // Count how many instructions were removed
                            
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
            if (newMethods != null) {
                newClasses.add(ImmutableClassDef(
                    classDef.type,
                    classDef.accessFlags,
                    classDef.superclass,
                    classDef.interfaces,
                    classDef.sourceFile,
                    classDef.annotations,
                    classDef.fields,
                    newMethods
                ))
            } else {
                newClasses.add(classDef)
            }
        }

        if (modified) {
            val newDexFile = ImmutableDexFile(loadedDexFile.opcodes, newClasses)
            DexFileFactory.writeDexFile(dexFile.absolutePath, newDexFile)
        }
        
        // Print summary after processing the DEX file
        if (removedCount > 0) {
            println("  - Removed $removedCount JNI bridge calls from ${dexFile.name}")
        }
    }

    private fun isJniBridgeClinitCall(instruction: Instruction): Boolean {
        // Check if it's an invoke-static instruction
        if (instruction.opcode.name == "invoke-static") {
            // All invoke instructions implement ReferenceInstruction and have a reference field
            if (instruction is org.jf.dexlib2.iface.instruction.ReferenceInstruction) {
                val ref = instruction.reference
                // Check if the reference is a MethodReference
                if (ref is MethodReference) {
                    return ref.name == "clinit" && ref.definingClass.contains("JniBridge")
                }
            }
        }
        return false
    }
}
