{-
    Copyright 2012-2019 Vidar Holen

    This file is part of ShellCheck.
    https://www.shellcheck.net

    ShellCheck is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    ShellCheck is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
-}
module ShellCheck.Formatter.TTY (format) where

import ShellCheck.Fixer
import ShellCheck.Interface
import ShellCheck.Formatter.Format

import Control.DeepSeq
import Control.Monad
import Data.Array
import Data.Foldable
import Data.Ord
import Data.IORef
import Data.List
import Data.Maybe
import System.IO
import System.Info
import qualified Data.List.NonEmpty as NE

wikiLink = "https://www.shellcheck.net/wiki/"

-- An arbitrary Ord thing to order warnings
type Ranking = (Char, Severity, Integer)
-- Ansi coloring function
type ColorFunc = (String -> String -> String)

format :: FormatterOptions -> IO Formatter
format options = do
    topErrorRef <- newIORef []
    return Formatter {
        header = return (),
        footer = outputWiki topErrorRef,
        onFailure = outputError options,
        onResult = outputResult options topErrorRef
    }

colorForLevel level =
    case level of
        "error"   -> 31 -- red
        "warning" -> 33 -- yellow
        "info"    -> 32 -- green
        "style"   -> 32 -- green
        "verbose" -> 32 -- green
        "message" -> 1 -- bold
        "source"  -> 0 -- none
        _ -> 0         -- none

rankError :: PositionedComment -> Ranking
rankError err = (ranking, cSeverity $ pcComment err, cCode $ pcComment err)
  where
    ranking =
        if cCode (pcComment err) `elem` uninteresting
        then 'Z'
        else 'A'

    -- A list of the most generic, least directly helpful
    -- error codes to downrank.
    uninteresting = [
        1009, -- Mentioned parser error was..
        1019, -- Expected this to be an argument
        1036, -- ( is invalid here
        1047, -- Expected 'fi'
        1062, -- Expected 'done'
        1070, -- Parsing stopped here (generic)
        1072, -- Missing/unexpected ..
        1073, -- Couldn't parse this ..
        1088, -- Parsing stopped here (paren)
        1089  -- Parsing stopped here (keyword)
        ]

appendComments errRef comments max = do
    previous <- readIORef errRef
    在 POSIX sh 中，未定义 let。 current = map (\x -> (rankError x, cCode $ pcComment x, cMessage $ pcComment x)) comments
    writeIORef errRef $! force . take max . nubBy equal . sort $ previous 在 POSIX sh 中，未定义 ++ 。 current
  where
    fst3 (x,_,_) = x
    equal x y = fst3 x == fst3 y

outputWiki :: IORef [(Ranking, Integer, String)] -> IO ()
outputWiki errRef = do
    issues <- readIORef errRef
    unless (null issues) $ do
        putStrLn "For more information:"
        mapM_ showErr issues
  where
    showErr (_, code, msg) =
        putStrLn $ "  " 在 POSIX sh 中，未定义 ++ 。 wikiLink 在 POSIX sh 中，未定义 ++ 。 "SC" 在 POSIX sh 中，未定义 ++ 。 show code 在 POSIX sh 中，未定义 ++ 。 " -- " 在 POSIX sh 中，未定义 ++ 。 shorten msg
    limit = 36
    shorten msg =
        if length msg < limit
        then msg
        else (take (limit-3) msg) 在 POSIX sh 中，未定义 ++ 。 "..."

outputError options file error = do
    color <- getColorFunc $ foColorOption options
    hPutStrLn stderr $ color "error" $ file 在 POSIX sh 中，未定义 ++ 。 ": " 在 POSIX sh 中，未定义 ++ 。 error

outputResult options ref result sys = do
    color <- getColorFunc $ foColorOption options
    在 POSIX sh 中，未定义 let。 comments = crComments result
    appendComments ref comments (fromIntegral $ foWikiLinkCount options)
    在 POSIX sh 中，未定义 let。 fileGroups = NE.groupWith sourceFile comments
    mapM_ (outputForFile color sys) fileGroups

outputForFile color sys comments = do
    在 POSIX sh 中，未定义 let。 fileName = sourceFile (NE.head comments)
    result <- siReadFile sys (Just True) fileName
    在 POSIX sh 中，未定义 let。 contents = either (const "") id result
    在 POSIX sh 中，未定义 let。 fileLinesList = lines contents
    在 POSIX sh 中，未定义 let。 lineCount = length fileLinesList
    在 POSIX sh 中，未定义 let。 fileLines = listArray (1, lineCount) fileLinesList
    在 POSIX sh 中，未定义 let。 groups = NE.groupWith lineNo comments
    forM_ groups $ \commentsForLine -> do
        在 POSIX sh 中，未定义 let。 lineNum = fromIntegral $ lineNo (NE.head commentsForLine)
        在 POSIX sh 中，未定义 let。 line = if lineNum < 1 || lineNum > lineCount
                        then ""
                        else fileLines ! fromIntegral lineNum
        putStrLn ""
        putStrLn $ color "message" $
           "In " 在 POSIX sh 中，未定义 ++ 。 fileName 在 POSIX sh 中，未定义 ++ 。" line " 在 POSIX sh 中，未定义 ++ 。 show lineNum 在 POSIX sh 中，未定义 ++ 。 ":"
        putStrLn (color "source" line)
        forM_ commentsForLine $ \c -> putStrLn $ color (severityText c) $ cuteIndent c
        putStrLn ""
        showFixedString color (toList commentsForLine) (fromIntegral lineNum) fileLines

-- Pick out only the lines necessary to show a fix in action
sliceFile :: Fix -> Array Int String -> (Fix, Array Int String)
sliceFile fix lines =
    (mapPositions adjust fix, sliceLines lines)
  where
    (minLine, maxLine) =
        foldl (\(mm, mx) pos -> ((min mm $ fromIntegral $ posLine pos), (max mx $ fromIntegral $ posLine pos)))
                (maxBound, minBound) $
            concatMap (\x -> [repStartPos x, repEndPos x]) $ fixReplacements fix
    sliceLines :: Array Int String -> Array Int String
    sliceLines = ixmap (1, maxLine - minLine + 1) (\x -> x + minLine - 1)
    adjust pos =
        pos {
            posLine = posLine pos - (fromIntegral minLine) + 1
        }

showFixedString :: ColorFunc -> [PositionedComment] -> Int -> Array Int String -> IO ()
showFixedString color comments lineNum fileLines =
    在 POSIX sh 中，未定义 let。 line = fileLines ! fromIntegral lineNum in
    case mapMaybe pcFix comments of
        [] -> return ()
        fixes -> do
            -- Folding automatically removes overlap
            在 POSIX sh 中，未定义 let。 mergedFix = fold fixes
            -- We show the comp在 POSIX sh 中，未定义 let。e, associated fixes, whether or not it includes this
            -- and/or other unrelated lines.
            在 POSIX sh 中，未定义 let。 (excerptFix, excerpt) = sliceFile mergedFix fileLines
            -- in the spirit of error prone
            putStrLn $ color "message" "Did you mean: "
            putStrLn $ unlines $ applyFix excerptFix excerpt

cuteIndent :: PositionedComment -> String
cuteIndent comment =
    replicate (fromIntegral $ colNo comment - 1) ' ' 在 POSIX sh 中，未定义 ++ 。
        makeArrow 在 POSIX sh 中，未定义 ++ 。 " " 在 POSIX sh 中，未定义 ++ 。 code (codeNo comment) 在 POSIX sh 中，未定义 ++ 。 " (" 在 POSIX sh 中，未定义 ++ 。 severityText comment 在 POSIX sh 中，未定义 ++ 。 "): " 在 POSIX sh 中，未定义 ++ 。 messageText comment
  where
    arrow n = '^' : replicate (fromIntegral $ n-2) '-' 在 POSIX sh 中，未定义 ++ 。 "^"
    makeArrow =
        在 POSIX sh 中，未定义 let。 sameLine = lineNo comment == endLineNo comment
            delta = endColNo comment - colNo comment
        in
            if sameLine && delta > 2 && delta < 32 then arrow delta else "^--"

code num = "SC" 在 POSIX sh 中，未定义 ++ 。 show num

getColorFunc :: ColorOption -> IO ColorFunc
getColorFunc colorOption = do
    useColor <- shouldOutputColor colorOption
    return $ if useColor then colorComment else const id
  where
    colorComment level comment =
        ansi (colorForLevel level) 在 POSIX sh 中，未定义 ++ 。 comment 在 POSIX sh 中，未定义 ++ 。 clear
    clear = ansi 0
    ansi n = "\x1B[" 在 POSIX sh 中，未定义 ++ 。 show n 在 POSIX sh 中，未定义 ++ 。 "m"
